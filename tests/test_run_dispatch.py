"""Run dispatch — the API/runner hand-off via ``run_queue``.

Proves the two dispatch modes and the isolated-runner claim/execute/finish path:

* ``inline`` (default) launches the in-process worker and enqueues NOTHING;
* ``queue`` enqueues exactly one ``run_queue`` row atomically with the PENDING run
  and does NOT launch in-process (the sidecar owns execution);
* ``claim_next`` claims oldest-first, stamps the claim, and returns ``None`` when
  drained (no double-claim);
* the runner loop executes each claimed run via ``execute_run`` and clears its
  queue row on completion.

The gate is upstream of all of this (proven in ``test_gate``): a run only reaches
the queue after every target is authorized.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.run import Run, RunStatus
from app.models.run_queue import RunQueueEntry
from app.core.config import get_settings
from app.schemas.run import RunCreate
from tests.conftest import make_engagement, make_org, make_target

ACTOR = "system:test"
IN_SCOPE = "https://example.com/login"


async def _seed_active_engagement(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org, value="example.com")
    eng = await make_engagement(db_session, org)
    return org, eng


async def _queue_count(session) -> int:
    return int(await session.scalar(select(func.count()).select_from(RunQueueEntry)) or 0)


# ---------------------------------------------------------------------------
# Dispatch mode selection
# ---------------------------------------------------------------------------
async def test_queue_mode_enqueues_and_does_not_launch_inline(db_session, monkeypatch):
    from app.services import runs as runs_service

    launched: dict = {}
    monkeypatch.setattr(runs_service, "launch_run_background", lambda **kw: launched.update(kw))
    monkeypatch.setattr(get_settings(), "run_dispatch_mode", "queue")

    _org, eng = await _seed_active_engagement(db_session)
    run = await runs_service.start_run(
        db_session, engagement=eng, actor=ACTOR, data=RunCreate(targets=[IN_SCOPE])
    )

    assert run.status == RunStatus.PENDING
    # In-process worker was NOT launched — the sidecar will pick it up.
    assert launched == {}
    # Exactly one queue row, bound to this run/org/engagement.
    assert await _queue_count(db_session) == 1
    entry = (await db_session.execute(select(RunQueueEntry))).scalar_one()
    assert entry.run_id == run.id
    assert entry.org_id == run.org_id
    assert entry.engagement_id == eng.id
    assert entry.claimed_at is None


async def test_inline_mode_launches_and_does_not_enqueue(db_session, monkeypatch):
    from app.services import runs as runs_service

    launched: dict = {}
    monkeypatch.setattr(runs_service, "launch_run_background", lambda **kw: launched.update(kw))
    monkeypatch.setattr(get_settings(), "run_dispatch_mode", "inline")

    _org, eng = await _seed_active_engagement(db_session)
    run = await runs_service.start_run(
        db_session, engagement=eng, actor=ACTOR, data=RunCreate(targets=[IN_SCOPE])
    )

    assert launched.get("run_id") == run.id
    assert await _queue_count(db_session) == 0


# ---------------------------------------------------------------------------
# claim_next / enqueue / mark_done
# ---------------------------------------------------------------------------
async def test_claim_next_claims_each_once_then_drains(db_session, monkeypatch):
    from app.repositories.run_queue import claim_next, mark_done
    from app.services import runs as runs_service

    monkeypatch.setattr(runs_service, "launch_run_background", lambda **kw: None)
    monkeypatch.setattr(get_settings(), "run_dispatch_mode", "queue")

    _org, eng = await _seed_active_engagement(db_session)
    run_a = await runs_service.start_run(
        db_session, engagement=eng, actor=ACTOR, data=RunCreate(targets=[IN_SCOPE])
    )
    run_b = await runs_service.start_run(
        db_session, engagement=eng, actor=ACTOR, data=RunCreate(targets=[IN_SCOPE])
    )

    # Each queued run is claimed exactly once (no double-claim); the claim is stamped.
    # (Strict FIFO ordering is a created_at guarantee, exercised in Postgres where
    # now() is sub-second — SQLite's coarse clock ties, so assert the set, not order.)
    first = await claim_next(db_session, worker_id="w1")
    second = await claim_next(db_session, worker_id="w1")
    assert first is not None and second is not None
    assert {first.run_id, second.run_id} == {run_a.id, run_b.id}
    assert all(c.claimed_by == "w1" and c.claimed_at is not None for c in (first, second))

    # Queue drained — nothing left to claim.
    assert await claim_next(db_session, worker_id="w1") is None

    # Finishing a run removes its queue row.
    await mark_done(db_session, run_id=run_a.id)
    await db_session.flush()
    assert await _queue_count(db_session) == 1


# ---------------------------------------------------------------------------
# The runner loop: claim -> execute_run -> clear queue row
# ---------------------------------------------------------------------------
async def test_runner_processes_queued_runs(db_session, monkeypatch):
    from app.runner import loop as runner_loop
    from app.services import runs as runs_service

    monkeypatch.setattr(runs_service, "launch_run_background", lambda **kw: None)
    monkeypatch.setattr(get_settings(), "run_dispatch_mode", "queue")

    _org, eng = await _seed_active_engagement(db_session)
    run = await runs_service.start_run(
        db_session, engagement=eng, actor=ACTOR, data=RunCreate(targets=[IN_SCOPE])
    )
    assert await _queue_count(db_session) == 1

    # Point the runner's sessionmaker at the test engine, and stub the actual scan.
    test_factory = async_sessionmaker(
        bind=db_session.bind, class_=AsyncSession, expire_on_commit=False
    )
    monkeypatch.setattr(runner_loop, "get_sessionmaker", lambda: test_factory)

    executed: list[dict] = []

    async def _fake_execute_run(**kw):
        executed.append(kw)

    monkeypatch.setattr(runner_loop, "execute_run", _fake_execute_run)

    claimed = await runner_loop._claim_one()
    assert claimed is not None and claimed["run_id"] == run.id
    await runner_loop._process(claimed)

    # execute_run got the run + threaded org context; queue row cleared afterwards.
    assert len(executed) == 1
    assert executed[0]["run_id"] == run.id
    assert executed[0]["org_id"] == run.org_id
    assert executed[0]["engagement_id"] == eng.id
    assert await _queue_count(db_session) == 0
