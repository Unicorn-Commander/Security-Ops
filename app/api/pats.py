"""Personal Access Token routes — the console's agent-key management (spec §6).

Endpoints (all under ``/api/v1``; every route requires SSO + the ``security-ops``
entitlement, enforced transitively via ``CurrentOrg``):

    POST   /pats            -> PATCreated (201)  [plaintext returned ONCE]
    GET    /pats            -> Page[PATRead]     (the caller's keys, non-secret)
    DELETE /pats/{pat_id}   -> PATRead           (revoke; idempotent)

A PAT lets a human mint a durable credential an AGENT then presents to the MCP
server (``/mcp/``) to drive Security-Ops with the operator's own authority. The
minted key inherits the operator's tenant (``org_slug``) and — unless the request
narrows them — the operator's entitlement SKUs as its ``scopes``, so an agent can
never exceed the person who created it. The plaintext token is surfaced exactly
once, in the creation response; only its hash is stored (see :mod:`app.security.pat`).
"""

import uuid

from fastapi import APIRouter, status

from app.api.deps import CurrentOrg, DbSession, EntitledUser
from app.core.errors import NotFoundError
from app.schemas.common import Page
from app.schemas.pat import PATCreate, PATCreated, PATRead
from app.security.pat import create_pat, list_pats, revoke_pat

router = APIRouter(tags=["pats"])


@router.post("/pats", response_model=PATCreated, status_code=status.HTTP_201_CREATED)
async def create_pat_route(
    data: PATCreate,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> PATCreated:
    """Mint an agent key for the current operator; returns the plaintext ONCE.

    ``scopes`` defaults to the operator's own entitlement SKUs (so the key carries
    the ``security-ops`` entitlement and nothing more) when the body leaves it
    empty. The key is bound to the caller's org. The route owns the commit.
    """
    scopes = data.scopes or list(user.apps)
    minted = await create_pat(
        session,
        user.id,
        data.name,
        scopes,
        data.expires_at,
        org_slug=org.slug,
        owner_email=user.email,
    )
    await session.commit()
    read = PATRead.model_validate(minted.record)
    return PATCreated(**read.model_dump(), token=minted.plaintext)


@router.get("/pats", response_model=Page[PATRead])
async def list_pats_route(
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> Page[PATRead]:
    """List the caller's PATs for this org (non-secret metadata), newest first."""
    items = await list_pats(session, owner_user_id=user.id, org_slug=org.slug)
    reads = [PATRead.model_validate(p) for p in items]
    return Page[PATRead](items=reads, total=len(reads), limit=len(reads), offset=0)


@router.delete("/pats/{pat_id}", response_model=PATRead)
async def revoke_pat_route(
    pat_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> PATRead:
    """Revoke one of the caller's PATs (idempotent). Cross-owner/org == 404."""
    record = await revoke_pat(
        session, pat_id, owner_user_id=user.id, org_slug=org.slug
    )
    if record is None:
        raise NotFoundError("Personal access token not found")
    await session.commit()
    return PATRead.model_validate(record)
