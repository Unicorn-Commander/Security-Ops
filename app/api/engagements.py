"""Engagement lifecycle + scope-of-engagement routes (spec §4/§6).

Endpoints (all under ``/api/v1``; every route requires SSO + the
``security-ops`` entitlement, enforced transitively via ``CurrentOrg``):

    POST   /engagements                          -> EngagementRead (201)
    GET    /engagements                          -> Page[EngagementRead]
    GET    /engagements/{engagement_id}          -> EngagementRead
    POST   /engagements/{engagement_id}/activate -> EngagementRead
    POST   /engagements/{engagement_id}/stop     -> EngagementRead (emergency stop)
    POST   /engagements/{engagement_id}/scope/check -> ScopeDecisionRead (dry-run)
    GET    /engagements/{engagement_id}/report   -> 501 (Phase 2)

The scope/check route is a *dry-run* of the gate: it calls the pure
``app.authz.gate.check_scope`` (NO audit write, NO raise) so previewing a
decision never emits a SCOPE_CHECK_DENIED side effect. Real enforcement
happens only on run creation (see ``app.api.runs``).
"""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Query, status
from fastapi.responses import PlainTextResponse

from app.api.deps import CurrentOrg, DbSession, EntitledUser
from app.authz.gate import check_scope
from app.core.errors import NotFoundError
from app.repositories.engagements import EngagementRepository
from app.schemas.common import Page
from app.schemas.engagement import (
    EngagementCreate,
    EngagementRead,
    ScopeCheckRequest,
    ScopeDecisionRead,
)
from app.services.engagements import (
    activate_engagement,
    create_engagement,
    emergency_stop,
)
from app.services.reports import generate_engagement_report

router = APIRouter(tags=["engagements"])


async def _load_engagement(session, engagement_id: uuid.UUID, org):
    """Fetch an engagement, enforcing tenant isolation (cross-org == 404)."""
    engagement = await EngagementRepository(session).get(engagement_id)
    if engagement is None or engagement.org_id != org.id:
        raise NotFoundError("Engagement not found")
    return engagement


@router.post(
    "/engagements",
    response_model=EngagementRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_engagement_route(
    data: EngagementCreate,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> EngagementRead:
    """Create a DRAFT engagement with its scope-of-engagement (audited)."""
    engagement = await create_engagement(session, org=org, actor=user, data=data)
    return EngagementRead.model_validate(engagement)


@router.get("/engagements", response_model=Page[EngagementRead])
async def list_engagements_route(
    session: DbSession,
    org: CurrentOrg,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[EngagementRead]:
    items, total = await EngagementRepository(session).list_for_org(
        org.id, limit=limit, offset=offset
    )
    return Page[EngagementRead](
        items=[EngagementRead.model_validate(e) for e in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/engagements/{engagement_id}", response_model=EngagementRead)
async def get_engagement_route(
    engagement_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
) -> EngagementRead:
    engagement = await _load_engagement(session, engagement_id, org)
    return EngagementRead.model_validate(engagement)


@router.post("/engagements/{engagement_id}/activate", response_model=EngagementRead)
async def activate_engagement_route(
    engagement_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> EngagementRead:
    """Activate an engagement; the service requires every in-scope rule to be
    covered by a valid attested target (else 422)."""
    engagement = await _load_engagement(session, engagement_id, org)
    activated = await activate_engagement(session, engagement=engagement, actor=user)
    return EngagementRead.model_validate(activated)


@router.post("/engagements/{engagement_id}/stop", response_model=EngagementRead)
async def stop_engagement_route(
    engagement_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> EngagementRead:
    """Emergency-stop an engagement (sets emergency_stopped + STOPPED, audited)."""
    engagement = await _load_engagement(session, engagement_id, org)
    stopped = await emergency_stop(session, engagement=engagement, actor=user)
    return EngagementRead.model_validate(stopped)


@router.post(
    "/engagements/{engagement_id}/scope/check",
    response_model=ScopeDecisionRead,
)
async def scope_check_route(
    engagement_id: uuid.UUID,
    data: ScopeCheckRequest,
    session: DbSession,
    org: CurrentOrg,
) -> ScopeDecisionRead:
    """Dry-run the authorization gate for a target: pure evaluation, no audit,
    no raise. Used by the UI to preview a decision before starting a run."""
    await _load_engagement(session, engagement_id, org)
    decision = await check_scope(session, engagement_id, data.target)
    return ScopeDecisionRead.model_validate(decision)


@router.get("/engagements/{engagement_id}/report")
async def engagement_report_route(
    engagement_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
    format: Annotated[Literal["markdown", "json"], Query()] = "markdown",
):
    """Export the branded engagement report (spec §8).

    Tenant-checked via ``_load_engagement`` (cross-org == 404). ``format=markdown``
    (default) returns the Markdown as ``text/markdown``; ``format=json`` returns
    ``{"engagement_id", "report_markdown"}`` for programmatic callers. The report is
    read-only — no run/finding rows are mutated.
    """
    engagement = await _load_engagement(session, engagement_id, org)
    report_markdown = await generate_engagement_report(session, engagement=engagement)
    if format == "json":
        return {
            "engagement_id": str(engagement.id),
            "report_markdown": report_markdown,
        }
    return PlainTextResponse(report_markdown, media_type="text/markdown")
