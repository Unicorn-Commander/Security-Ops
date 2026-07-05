"""Finding read + Brigade hand-off routes (spec §6/§8).

Endpoints (all under ``/api/v1``; every route requires SSO + the
``security-ops`` entitlement, enforced transitively via ``CurrentOrg``):

    GET    /findings/{finding_id}          -> FindingRead
    POST   /findings/{finding_id}/handoff  -> 501 (Phase 2 Brigade hand-off)

Findings carry a denormalized ``org_id`` (for row-level isolation), which the
read/handoff routes check so a caller can only ever see their own org's data.
"""

import uuid

from fastapi import APIRouter, status

from app.api.deps import CurrentOrg, DbSession
from app.core.errors import AppError, NotFoundError
from app.repositories.findings import FindingRepository
from app.schemas.finding import FindingRead

router = APIRouter(tags=["findings"])


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


@router.post(
    "/findings/{finding_id}/handoff",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
)
async def handoff_finding_route(
    finding_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
):
    """Hand a confirmed finding to Brigade for triage/remediation.

    Wired in Phase 2 (Security-Ops finds; Brigade fixes). Tenant-checked so a
    missing/cross-org finding still reports 404 rather than 501.
    """
    finding = await FindingRepository(session).get(finding_id)
    if finding is None or finding.org_id != org.id:
        raise NotFoundError("Finding not found")
    raise AppError(
        "Brigade hand-off lands in Phase 2.",
        code="not_implemented",
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
    )
