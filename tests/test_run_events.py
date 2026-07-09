"""Live run-trace (SSE step log) — model/repo, emitter, reasoning tail, endpoint.

Covers the append-only ``run_events`` transport end to end WITHOUT a live scan:

* :class:`RunEventRepository` assigns a monotonic per-run ``seq`` and the SSE tail
  query (``list_after``) returns only newer events in order;
* the emitter (:func:`emit_run_event` / :func:`emit_run_events`) writes through its
  OWN committed session (proved by pointing its sessionmaker at the test engine);
* the runner's reasoning tail (``StrixRunner._emit_log_lines``) parses only whole
  lines and leaves a partial tail for the next tick;
* the SSE endpoint replays a terminal run's events then closes, tails a running
  run until the client disconnects, and renders a cross-org run as 404.

Everything runs on the in-memory sqlite fixture — no Postgres, no subprocess.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.runs import stream_run_events_route
from app.core.config import get_settings
from app.core.errors import NotFoundError
from app.engine.strix_runner import StrixRunner
from app.models.run import Run, RunMode, RunStatus
from app.models.run_event import RunEventType
from app.repositories.run_events import RunEventRepository
from tests.conftest import make_engagement, make_org

pytestmark = pytest.mark.asyncio


async def _make_run(session: AsyncSession, org, eng, *, status=RunStatus.RUNNING) -> Run:
    run = Run(
        id=uuid.uuid4(),
        engagement_id=eng.id,
        org_id=org.id,
        engine="strix",
        mode=RunMode.STANDARD,
        model_profile="hybrid-local-sweep-verify",
        targets=["https://example.com/login"],
        status=status,
    )
    session.add(run)
    await session.flush()
    return run


class _FakeRequest:
    """Minimal stand-in for starlette's Request — the SSE route only needs
    ``is_disconnected()``. ``drop_after`` returns True on the Nth call so a
    running-run stream test terminates deterministically instead of looping."""

    def __init__(self, drop_after: int | None = None) -> None:
        self._drop_after = drop_after
        self._calls = 0

    async def is_disconnected(self) -> bool:
        self._calls += 1
        return self._drop_after is not None and self._calls > self._drop_after


async def _collect(response) -> str:
    parts = []
    async for chunk in response.body_iterator:
        parts.append(chunk.decode() if isinstance(chunk, (bytes, bytearray)) else chunk)
    return "".join(parts)


# ---------------------------------------------------------------------------
# Repository — monotonic seq + tail query
# ---------------------------------------------------------------------------
async def test_append_assigns_monotonic_seq_and_lists_after(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    run = await _make_run(db_session, org, eng)
    repo = RunEventRepository(db_session)

    assert await repo.latest_seq(run.id) == 0
    e1 = await repo.append(run_id=run.id, org_id=org.id, event_type="queued")
    e2 = await repo.append(run_id=run.id, org_id=org.id, event_type="running")
    e3 = await repo.append(run_id=run.id, org_id=org.id, event_type="finding")
    assert [e1.seq, e2.seq, e3.seq] == [1, 2, 3]
    assert await repo.latest_seq(run.id) == 3

    # The exact SSE tail query: only events past the cursor, in order.
    after1 = await repo.list_after(run.id, 1)
    assert [e.seq for e in after1] == [2, 3]
    assert [e.seq for e in await repo.list_after(run.id, 3)] == []
    assert [e.seq for e in await repo.list_for_run(run.id)] == [1, 2, 3]


async def test_seq_is_per_run_not_global(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    run_a = await _make_run(db_session, org, eng)
    run_b = await _make_run(db_session, org, eng)
    repo = RunEventRepository(db_session)

    await repo.append(run_id=run_a.id, org_id=org.id, event_type="queued")
    await repo.append(run_id=run_a.id, org_id=org.id, event_type="running")
    b1 = await repo.append(run_id=run_b.id, org_id=org.id, event_type="queued")

    # run_b's first event is seq 1 even though run_a already has two events.
    assert b1.seq == 1
    assert await repo.latest_seq(run_a.id) == 2


# ---------------------------------------------------------------------------
# Emitter — writes through its OWN committed session
# ---------------------------------------------------------------------------
async def test_emit_run_event_writes_via_own_session(db_session, monkeypatch):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    run = await _make_run(db_session, org, eng)
    await db_session.commit()

    import app.services.run_events as svc

    factory = async_sessionmaker(
        bind=db_session.bind, class_=AsyncSession, expire_on_commit=False
    )
    monkeypatch.setattr(svc, "get_sessionmaker", lambda: factory)

    seq = await svc.emit_run_event(
        run_id=run.id, org_id=org.id, event_type=RunEventType.RUNNING, message="go"
    )
    assert seq == 1

    # Visible from the fixture session (shared in-memory connection).
    events = await RunEventRepository(db_session).list_for_run(run.id)
    assert [(e.seq, e.event_type, e.message) for e in events] == [(1, "running", "go")]


async def test_emit_run_events_batch_is_contiguous(db_session, monkeypatch):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    run = await _make_run(db_session, org, eng)
    await db_session.commit()

    import app.services.run_events as svc

    factory = async_sessionmaker(
        bind=db_session.bind, class_=AsyncSession, expire_on_commit=False
    )
    monkeypatch.setattr(svc, "get_sessionmaker", lambda: factory)

    last = await svc.emit_run_events(
        run_id=run.id,
        org_id=org.id,
        events=[
            (RunEventType.REASONING, "line-1", None),
            (RunEventType.REASONING, "line-2", None),
            (RunEventType.REASONING, "line-3", None),
        ],
    )
    assert last == 3
    events = await RunEventRepository(db_session).list_for_run(run.id)
    assert [e.seq for e in events] == [1, 2, 3]
    assert all(e.event_type == "reasoning" for e in events)


async def test_emit_failure_is_swallowed(db_session, monkeypatch):
    """A broken sessionmaker must never raise into the runner — returns None."""
    import app.services.run_events as svc

    def _boom():
        raise RuntimeError("db gone")

    monkeypatch.setattr(svc, "get_sessionmaker", _boom)
    result = await svc.emit_run_event(
        run_id=uuid.uuid4(), org_id=uuid.uuid4(), event_type="running"
    )
    assert result is None


# ---------------------------------------------------------------------------
# Reasoning tail — whole-line parsing, partial tail preserved
# ---------------------------------------------------------------------------
async def test_emit_log_lines_parses_whole_lines_only(db_session, monkeypatch, tmp_path):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    run = await _make_run(db_session, org, eng)

    captured: list[tuple] = []

    async def _capture(*, run_id, org_id, events):
        captured.extend(events)
        return len(events)

    import app.services.run_events as svc

    monkeypatch.setattr(svc, "emit_run_events", _capture)

    log = tmp_path / "run.log"
    # Two complete lines + a partial (no trailing newline).
    log.write_text("recon: enumerating\nfound login form\npartial-tail-no-nl")
    runner = StrixRunner(db_session)

    pos = await runner._emit_log_lines(run, log, 0)
    # Only the two complete lines are emitted; the partial is left for next tick.
    assert [msg for (_t, msg, _d) in captured] == ["recon: enumerating", "found login form"]
    assert all(t == RunEventType.REASONING for (t, _m, _d) in captured)

    # A second call from the returned offset with the line now completed emits it.
    captured.clear()
    log.write_text(
        "recon: enumerating\nfound login form\npartial-tail-no-nl NOW-DONE\n"
    )
    await runner._emit_log_lines(run, log, pos)
    assert [msg for (_t, msg, _d) in captured] == ["partial-tail-no-nl NOW-DONE"]


async def test_emit_log_lines_no_complete_line_returns_same_pos(db_session, tmp_path):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    run = await _make_run(db_session, org, eng)
    log = tmp_path / "run.log"
    log.write_text("no newline yet")
    runner = StrixRunner(db_session)
    assert await runner._emit_log_lines(run, log, 0) == 0


# ---------------------------------------------------------------------------
# SSE endpoint — replay + close, tail + disconnect, cross-org 404
# ---------------------------------------------------------------------------
async def test_sse_terminal_run_replays_then_ends(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    run = await _make_run(db_session, org, eng, status=RunStatus.COMPLETED)
    repo = RunEventRepository(db_session)
    for etype in ("queued", "running", "finding", "completed"):
        await repo.append(run_id=run.id, org_id=org.id, event_type=etype)
    await db_session.commit()

    resp = await stream_run_events_route(
        run.id, request=_FakeRequest(), session=db_session, org=org, after=0, last_event_id=None
    )
    body = await _collect(resp)

    # Opens with status, replays every event in order, then a terminal end frame.
    assert "event: open" in body
    for etype in ("queued", "running", "finding", "completed"):
        assert f"event: {etype}" in body
    assert "event: end" in body
    assert "COMPLETED" in body
    # Replay respects seq ordering.
    assert body.index("event: queued") < body.index("event: finding")


async def test_sse_resume_cursor_skips_seen_events(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    run = await _make_run(db_session, org, eng, status=RunStatus.COMPLETED)
    repo = RunEventRepository(db_session)
    for etype in ("queued", "running", "completed"):
        await repo.append(run_id=run.id, org_id=org.id, event_type=etype)
    await db_session.commit()

    # Last-Event-ID = 2 → only seq 3 (completed) should replay.
    resp = await stream_run_events_route(
        run.id, request=_FakeRequest(), session=db_session, org=org, after=0, last_event_id=2
    )
    body = await _collect(resp)
    assert "event: completed" in body
    assert "event: queued" not in body
    assert "id: 1" not in body


async def test_sse_running_run_tails_then_stops_on_disconnect(db_session, monkeypatch):
    monkeypatch.setattr(get_settings(), "sse_poll_seconds", 0.01)
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    run = await _make_run(db_session, org, eng, status=RunStatus.RUNNING)
    repo = RunEventRepository(db_session)
    await repo.append(run_id=run.id, org_id=org.id, event_type="running")
    await db_session.commit()

    # Non-terminal run would loop forever; the fake client disconnects after the
    # first poll so the stream ends deterministically (also exercises the
    # commit-between-polls snapshot refresh + heartbeat).
    resp = await stream_run_events_route(
        run.id, request=_FakeRequest(drop_after=1), session=db_session, org=org,
        after=0, last_event_id=None,
    )
    body = await _collect(resp)
    assert "event: open" in body
    assert "event: running" in body
    assert "heartbeat" in body
    # It stopped on disconnect, not on a terminal status.
    assert "event: end" not in body


async def test_sse_cross_org_is_404(db_session):
    org = await make_org(db_session, slug="tenant-a")
    other = await make_org(db_session, slug="tenant-b")
    eng = await make_engagement(db_session, org)
    run = await _make_run(db_session, org, eng, status=RunStatus.COMPLETED)
    await db_session.commit()

    with pytest.raises(NotFoundError):
        await stream_run_events_route(
            run.id, request=_FakeRequest(), session=db_session, org=other,
            after=0, last_event_id=None,
        )
