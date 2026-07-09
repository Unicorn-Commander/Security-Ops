"""Authorized-target registry + attestation routes (spec §4/§6).

Endpoints (all under ``/api/v1``; every route requires SSO + the
``security-ops`` entitlement, enforced transitively via ``CurrentOrg``):

    GET    /targets                        -> Page[TargetRead]
    POST   /targets                        -> TargetRead (201)
    GET    /targets/{target_id}            -> TargetRead
    POST   /targets/{target_id}/attest     -> TargetRead

The attest route is the only place the API calls the target-authz layer
(``app.authz.attestation.attest_target``) directly, so it owns the commit;
the create route delegates to the service layer, which owns its own commit.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, status

from app.api.deps import CurrentOrg, DbSession, EntitledUser
from app.auth.sso import UserRole
from app.authz.attestation import attest_target
from app.authz.cloud_proof import cloud_instructions
from app.authz.proof import proof_instructions
from app.core.errors import NotFoundError
from app.models.target import TargetKind
from app.repositories.targets import TargetRepository
from app.schemas.common import Page
from app.schemas.target import AttestationRequest, TargetCreate, TargetRead
from app.services.targets import list_targets, register_target

router = APIRouter(tags=["targets"])


@router.get("/targets", response_model=Page[TargetRead])
async def list_targets_route(
    session: DbSession,
    org: CurrentOrg,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[TargetRead]:
    """List the calling org's authorized targets (org-scoped in the service)."""
    items, total = await list_targets(session, org=org, limit=limit, offset=offset)
    return Page[TargetRead](
        items=[TargetRead.model_validate(t) for t in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/targets",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_target_route(
    data: TargetCreate,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> TargetRead:
    """Register a new (UNATTESTED) target; audited TARGET_REGISTERED by the service."""
    target = await register_target(session, org=org, actor=user, data=data)
    return TargetRead.model_validate(target)


@router.get("/targets/{target_id}", response_model=TargetRead)
async def get_target_route(
    target_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
) -> TargetRead:
    target = await TargetRepository(session).get(target_id)
    if target is None or target.org_id != org.id:
        raise NotFoundError("Target not found")
    return TargetRead.model_validate(target)


@router.get("/targets/{target_id}/attestation-challenge")
async def attestation_challenge_route(
    target_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
) -> dict:
    """Return the per-target challenge token + copy-paste proof instructions.

    For external targets the operator must publish this unpredictable token (a DNS
    TXT record, a well-known file, or a ``Strix-Authorization`` header) BEFORE
    attesting — the server independently verifies it (spec §4). Self-owned targets
    can skip this and attest via ``OWNED`` / typed confirmation instead.
    """
    target = await TargetRepository(session).get(target_id)
    if target is None or target.org_id != org.id:
        raise NotFoundError("Target not found")
    # Cloud accounts prove authorization by a role grant, not a published token, so
    # they get the CLOUD_ROLE instructions (external ID + trust-policy snippet).
    if target.kind == TargetKind.CLOUD_ACCOUNT:
        return cloud_instructions(target)
    return proof_instructions(target)


@router.post("/targets/{target_id}/attest", response_model=TargetRead)
async def attest_target_route(
    target_id: uuid.UUID,
    data: AttestationRequest,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> TargetRead:
    """Attest a target so the gate will treat it as scannable.

    Tenant isolation: only targets owned by the caller's org may be attested.
    ``attest_target`` (authz layer) performs the mutation + TARGET_ATTESTED
    audit but does not commit, so this route owns the transaction.
    """
    existing = await TargetRepository(session).get(target_id)
    if existing is None or existing.org_id != org.id:
        raise NotFoundError("Target not found")

    target = await attest_target(
        session,
        target_id,
        principal=user,
        method=data.method,
        checkbox_ack=data.checkbox_ack,
        typed_confirmation=data.typed_confirmation,
        justification=data.justification,
        evidence=data.evidence,
        expires_at=data.expires_at,
        actor_is_admin=user.role == UserRole.ADMIN,
    )
    await session.commit()
    return TargetRead.model_validate(target)
