"""Run lifecycle routes — GATE-ENFORCED run creation (spec §4/§6).

Endpoints (all under ``/api/v1``; every route requires SSO + the
``security-ops`` entitlement, enforced transitively via ``CurrentOrg``):

    POST   /engagements/{engagement_id}/runs -> RunRead (201)  [GATE-ENFORCED]
    GET    /runs                             -> Page[RunRead]   (org-scoped list)
    GET    /runs/{run_id}                    -> RunRead
    POST   /runs/{run_id}/stop               -> RunRead
    GET    /runs/{run_id}/findings           -> Page[FindingRead]

The ``GET /runs`` collection list is org-scoped and read-only (it powers the
console): it filters on the caller's org via ``CurrentOrg`` so a caller only
ever sees their own tenant's runs.

The run-start route delegates to ``app.services.runs.start_run``, which is the
authoritative server-side enforcement path: it calls
``app.authz.gate.enforce_scope`` for EVERY concrete target before any run row
is created. A gate denial raises an ``AuthorizationDenied`` (HTTP 403) that
propagates unchanged, so no RUNNING run is ever created for an unauthorized
target. The engine is never trusted to self-limit.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, status

from app.api.deps import CurrentOrg, DbSession, EntitledUser
from app.core.errors import NotFoundError
from app.repositories.engagements import EngagementRepository
from app.repositories.findings import FindingRepository
from app.repositories.runs import RunRepository
from app.schemas.common import Page
from app.schemas.finding import FindingRead
from app.schemas.run import RunCreate, RunRead
from app.models.run import RunStatus
from app.services.runs import get_run, start_run, stop_run

router = APIRouter(tags=["runs"])


async def _load_run(session, run_id: uuid.UUID, org):
    """Fetch a run, enforcing tenant isolation (cross-org == 404)."""
    run = await get_run(session, run_id)
    if run is None or run.org_id != org.id:
        raise NotFoundError("Run not found")
    return run


@router.post(
    "/engagements/{engagement_id}/runs",
    response_model=RunRead,
    status_code=status.HTTP_201_CREATED,
)
async def start_run_route(
    engagement_id: uuid.UUID,
    data: RunCreate,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> RunRead:
    """Start a scan run — THE gate-enforced path.

    Loads the engagement (tenant-checked), then hands off to
    ``services.runs.start_run`` which runs the authorization gate
    (``enforce_scope``) for each target in ``data.targets`` BEFORE creating any
    run. If the gate denies, a 403 propagates and no run is started.
    """
    engagement = await EngagementRepository(session).get(engagement_id)
    if engagement is None or engagement.org_id != org.id:
        raise NotFoundError("Engagement not found")

    run = await start_run(session, engagement=engagement, actor=user, data=data)
    return RunRead.model_validate(run)


@router.get("/runs", response_model=Page[RunRead])
async def list_runs_route(
    session: DbSession,
    org: CurrentOrg,
    status: Annotated[RunStatus | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[RunRead]:
    """Org-scoped list of the caller's runs, newest first (console).

    Filters on ``org.id`` in the repository (tenant isolation is the WHERE
    clause), with an optional ``status`` lifecycle filter. Read-only. Declared
    above ``/runs/{run_id}`` so the literal collection path is never shadowed by
    the parameterized route."""
    items, total = await RunRepository(session).list_for_org(
        org.id, status=status, limit=limit, offset=offset
    )
    return Page[RunRead](
        items=[RunRead.model_validate(r) for r in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/runs/{run_id}", response_model=RunRead)
async def get_run_route(
    run_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
) -> RunRead:
    run = await _load_run(session, run_id, org)
    return RunRead.model_validate(run)


@router.post("/runs/{run_id}/stop", response_model=RunRead)
async def stop_run_route(
    run_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> RunRead:
    """Stop a run (audited RUN_STOPPED)."""
    run = await _load_run(session, run_id, org)
    stopped = await stop_run(session, run=run, actor=user)
    return RunRead.model_validate(stopped)


@router.get("/runs/{run_id}/findings", response_model=Page[FindingRead])
async def list_run_findings_route(
    run_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[FindingRead]:
    await _load_run(session, run_id, org)
    items, total = await FindingRepository(session).list_for_run(
        run_id, limit=limit, offset=offset
    )
    return Page[FindingRead](
        items=[FindingRead.model_validate(f) for f in items],
        total=total,
        limit=limit,
        offset=offset,
    )
