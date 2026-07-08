"""Finding read + Brigade hand-off routes (spec §6/§8).

Endpoints (all under ``/api/v1``; every route requires SSO + the
``security-ops`` entitlement, enforced transitively via ``CurrentOrg``):

    GET    /findings                       -> Page[FindingRead] (org-scoped inbox)
    GET    /findings/{finding_id}          -> FindingRead
    POST   /findings/{finding_id}/status   -> FindingRead (operator triage)
    POST   /findings/{finding_id}/handoff  -> FindingRead (hands to Brigade)

The ``GET /findings`` collection list is the org-scoped, read-only findings
inbox the console renders; it filters on the caller's org via ``CurrentOrg`` so a
caller only ever sees their own tenant's findings. It is declared ABOVE the
``/findings/{finding_id}`` param route so the literal collection path is never
shadowed.

Findings carry a denormalized ``org_id`` (for row-level isolation), which the
read/handoff routes check so a caller can only ever see their own org's data.
"Security-Ops *finds*; Brigade *fixes*" — the hand-off turns a confirmed finding
into a Brigade agent task (triage / ticket / remediation PR). If no Brigade
intake endpoint is configured (``settings.brigade_base_url`` unset), the
orchestrator surfaces an honest 501 rather than pretending to hand off.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import CurrentOrg, DbSession, EntitledUser
from app.core.errors import NotFoundError
from app.engine.brigade_handoff import handoff_finding
from app.models.finding import FindingSeverity, FindingStatus
from app.repositories.engagements import EngagementRepository
from app.repositories.findings import FindingRepository
from app.repositories.runs import RunRepository
from app.schemas.common import Page
from app.schemas.finding import FindingRead, FindingStatusUpdate
from app.services.findings import set_finding_status

router = APIRouter(tags=["findings"])


@router.get("/findings", response_model=Page[FindingRead])
async def list_findings_route(
    session: DbSession,
    org: CurrentOrg,
    severity: Annotated[FindingSeverity | None, Query()] = None,
    status: Annotated[FindingStatus | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[FindingRead]:
    """Org-scoped findings inbox, newest first (console).

    Filters on ``org.id`` in the repository (tenant isolation is the WHERE
    clause), with optional ``severity`` and ``status`` filters. Read-only.
    Declared above ``/findings/{finding_id}`` so the literal collection path is
    never shadowed by the parameterized route."""
    items, total = await FindingRepository(session).list_for_org(
        org.id, severity=severity, status=status, limit=limit, offset=offset
    )
    return Page[FindingRead](
        items=[FindingRead.model_validate(f) for f in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/findings/{finding_id}", response_model=FindingRead)
async def get_finding_route(
    finding_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
) -> FindingRead:
    finding = await FindingRepository(session).get(finding_id)
    if finding is None or finding.org_id != org.id:
        raise NotFoundError("Finding not found")
    return FindingRead.model_validate(finding)


@router.post("/findings/{finding_id}/status", response_model=FindingRead)
async def set_finding_status_route(
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> FindingRead:
    """Triage a finding — set its status (Mark verified / false positive / reopen).

    Tenant-checked (a missing/cross-org finding is 404). Delegates to
    ``app.services.findings.set_finding_status``, which flips the status and appends
    ONE ``FINDING_TRIAGED`` audit row on a real change (idempotent no-op when the
    status is unchanged). This route owns the commit. Setting ``HANDED_OFF`` via this
    path is refused with 422 — that transition belongs to ``/handoff``.
    """
    finding = await FindingRepository(session).get(finding_id)
    if finding is None or finding.org_id != org.id:
        raise NotFoundError("Finding not found")

    finding = await set_finding_status(
        session, finding=finding, new_status=body.status, actor=user
    )
    await session.commit()
    return FindingRead.model_validate(finding)


@router.post("/findings/{finding_id}/handoff", response_model=FindingRead)
async def handoff_finding_route(
    finding_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> FindingRead:
    """Hand a confirmed finding to Brigade for triage/remediation.

    Tenant-checked (a missing/cross-org finding is 404). Delegates to
    ``app.engine.brigade_handoff.handoff_finding``, which builds the agent-task
    payload, submits it, flips the finding to ``HANDED_OFF`` (recording
    ``handoff_ref``), and appends a ``FINDING_HANDOFF`` audit row. This route owns
    the commit. Surfaces the orchestrator's errors unchanged: 409 (already handed
    off), 422 (false positive / ineligible), 501 (Brigade not configured), 502
    (Brigade rejected the submission).
    """
    finding = await FindingRepository(session).get(finding_id)
    if finding is None or finding.org_id != org.id:
        raise NotFoundError("Finding not found")

    # Context for a richer Brigade payload (best-effort; hand-off works without it).
    engagement = None
    run = None
    if finding.engagement_id is not None:
        engagement = await EngagementRepository(session).get(finding.engagement_id)
    if finding.run_id is not None:
        run = await RunRepository(session).get(finding.run_id)

    finding = await handoff_finding(
        session,
        finding=finding,
        actor=user,
        engagement=engagement,
        run=run,
    )
    await session.commit()
    return FindingRead.model_validate(finding)
