"""Persistence for the run dispatch queue (:class:`app.models.run_queue.RunQueueEntry`).

Two sides:

* ``enqueue`` — the API side. Adds a queue row to the CURRENT session so it commits
  atomically with the gate-cleared PENDING run (the caller owns the commit).
* ``claim_next`` — the runner side. Atomically claims the oldest available row with
  ``FOR UPDATE SKIP LOCKED`` so N runners never double-claim; ``mark_done`` removes
  the row once the run reaches a terminal status (the ``runs`` row is the durable
  record — the queue is just the hand-off).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.run_queue import RunQueueEntry


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def enqueue(
    session: AsyncSession,
    *,
    run_id: uuid.UUID,
    org_id: uuid.UUID,
    engagement_id: uuid.UUID,
    scope_mode: str | None = None,
    diff_base: str | None = None,
) -> RunQueueEntry:
    """Add a dispatch row for a gate-cleared PENDING run (caller commits).

    Kept in the same transaction as the ``runs`` insert so a run and its dispatch
    are durable together — an API crash can never strand a committed run with no
    queue entry (nor enqueue a run that rolled back).
    """
    entry = RunQueueEntry(
        run_id=run_id,
        org_id=org_id,
        engagement_id=engagement_id,
        scope_mode=scope_mode,
        diff_base=diff_base,
    )
    session.add(entry)
    await session.flush()
    return entry


async def claim_next(session: AsyncSession, *, worker_id: str) -> RunQueueEntry | None:
    """Atomically claim the oldest unclaimed dispatch row, or ``None`` if empty.

    ``FOR UPDATE SKIP LOCKED`` selects one available row and locks it for this
    transaction; a concurrent runner skips the locked row and takes the next.
    The lock is held until the caller commits — so the caller should stamp the
    claim (done here) and commit promptly, then execute the run outside the lock.
    """
    stmt = (
        select(RunQueueEntry)
        .where(RunQueueEntry.claimed_at.is_(None))
        .order_by(RunQueueEntry.created_at.asc(), RunQueueEntry.id.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    entry = (await session.execute(stmt)).scalar_one_or_none()
    if entry is None:
        return None
    entry.claimed_at = _utcnow()
    entry.claimed_by = worker_id
    await session.flush()
    return entry


async def mark_done(session: AsyncSession, *, run_id: uuid.UUID) -> None:
    """Remove a run's dispatch row after it reaches a terminal status (caller commits)."""
    await session.execute(delete(RunQueueEntry).where(RunQueueEntry.run_id == run_id))
