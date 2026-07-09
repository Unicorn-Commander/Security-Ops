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

import asyncio
import json
import uuid
from typing import Annotated

from fastapi import APIRouter, Header, Query, Request, status
from fastapi.responses import StreamingResponse

from app.api.deps import CurrentOrg, DbSession, EntitledUser
from app.core.config import settings
from app.core.errors import NotFoundError
from app.repositories.engagements import EngagementRepository
from app.repositories.findings import FindingRepository
from app.repositories.run_events import RunEventRepository
from app.repositories.runs import RunRepository
from app.schemas.common import Page
from app.schemas.finding import FindingRead
from app.schemas.run import RunCreate, RunRead
from app.schemas.run_event import RunEventRead
from app.models.run import RunStatus
from app.services.runs import get_run, start_run, stop_run

router = APIRouter(tags=["runs"])

# A run is over: the SSE stream drains any final events then closes.
_TERMINAL_STATUSES = frozenset(
    {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.STOPPED, RunStatus.DENIED}
)


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


def _sse_frame(*, event: str, data: str, event_id: int | None = None) -> str:
    """Render one Server-Sent Event frame (``id:``/``event:``/``data:`` + blank line)."""
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    lines.append(f"data: {data}")
    return "\n".join(lines) + "\n\n"


@router.get("/runs/{run_id}/events")
async def stream_run_events_route(
    run_id: uuid.UUID,
    request: Request,
    session: DbSession,
    org: CurrentOrg,
    after: Annotated[int, Query(ge=0)] = 0,
    last_event_id: Annotated[int | None, Header(alias="Last-Event-ID")] = None,
) -> StreamingResponse:
    """Live trace of a run as Server-Sent Events (the console's step log).

    Replays the run's ``run_events`` in ``seq`` order from the resume cursor, then
    tails newly-appended rows until the run is terminal (or the client leaves).
    Tenant-isolated: a cross-org run reads as 404 (``_load_run``), and every poll
    runs through the org-bound request session so RLS confines the trace to the
    caller's org.

    Resume: the client's ``Last-Event-ID`` header (standard EventSource reconnect)
    wins over the ``?after=`` query param; either is the last ``seq`` already seen.

    Snapshot/GUC subtlety (Postgres): the poll loop ``commit()``s — never
    ``rollback()``s — between ticks. Commit both (a) ends the read transaction so
    the next poll sees rows other transactions committed (a repeated SELECT inside
    ONE transaction would never see them under snapshot isolation), and (b)
    PERSISTS the session-level ``app.current_org_id`` GUC set by ``get_current_org``
    (a rollback would revert that ``set_config`` and RLS would then hide every row).
    """
    run = await _load_run(session, run_id, org)
    start_seq = last_event_id if last_event_id is not None else after
    events_repo = RunEventRepository(session)
    runs_repo = RunRepository(session)

    poll = max(0.2, float(getattr(settings, "sse_poll_seconds", 1.0)))
    max_seconds = float(getattr(settings, "sse_max_seconds", 7200.0))

    async def _drain(cursor: int):
        """Yield ``(seq, sse_frame)`` for every event after ``cursor``.

        The caller advances its own cursor from the last yielded ``seq``."""
        for ev in await events_repo.list_after(run.id, cursor):
            payload = RunEventRead.model_validate(ev).model_dump_json()
            yield ev.seq, _sse_frame(event=ev.event_type, data=payload, event_id=ev.seq)

    async def event_stream():
        cursor = start_seq
        elapsed = 0.0
        # Announce the current status up front so a late subscriber has context.
        yield _sse_frame(
            event="open",
            data=json.dumps(
                {"run_id": str(run.id), "status": _status_value(run.status)}
            ),
        )
        while True:
            if await request.is_disconnected():
                return
            # Drain any events past the cursor (replay on first pass, tail after).
            async for seq, frame in _drain(cursor):
                cursor = seq
                yield frame

            fresh = await runs_repo.get(run.id)
            status_now = fresh.status if fresh is not None else run.status
            if status_now in _TERMINAL_STATUSES:
                # Close the write/flip race: an event may have landed AFTER the
                # drain above but BEFORE we read a terminal status. Drain once more.
                async for seq, frame in _drain(cursor):
                    cursor = seq
                    yield frame
                yield _sse_frame(
                    event="end", data=json.dumps({"status": _status_value(status_now)})
                )
                return

            if elapsed >= max_seconds:
                yield _sse_frame(
                    event="end",
                    data=json.dumps({"status": "timeout", "reason": "stream_max_seconds"}),
                )
                return

            # Heartbeat comment keeps intermediaries from closing an idle stream.
            yield ": heartbeat\n\n"
            # Commit (NOT rollback) → fresh snapshot next poll + keep the org GUC.
            await session.commit()
            await asyncio.sleep(poll)
            elapsed += poll

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Disable proxy buffering (nginx) so events flush immediately.
            "X-Accel-Buffering": "no",
        },
    )


def _status_value(status: object) -> str:
    return getattr(status, "value", str(status))
