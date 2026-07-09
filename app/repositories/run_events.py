"""RunEventRepository — data access for :class:`app.models.run_event.RunEvent`.

Thin async-SQLAlchemy-2.0 layer; like every repository it NEVER commits (the
caller owns the transaction). Two callers:

* the emitter (:func:`app.services.run_events.emit_run_event`) opens its own short
  org-bound session, calls :meth:`append`, and commits — so a trace line is
  durable and visible to readers immediately, independent of the runner's
  long-lived main-session transaction.
* the SSE endpoint reads with :meth:`list_after` / :meth:`list_for_run` through the
  request session (org-bound, so RLS confines it to the caller's tenant).

``seq`` is a per-run monotonic cursor. A run has exactly ONE writer (its runner
process), so computing "next seq = max(seq)+1" here is race-free without a DB
sequence, and gives the SSE client a stable resume cursor.

Dependency direction (no cycles): repositories -> {models, db}.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.run_event import RunEvent


class RunEventRepository:
    """Appends and reads a run's live trace. Construct per-request with the session."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def latest_seq(self, run_id: uuid.UUID) -> int:
        """Return the highest ``seq`` recorded for ``run_id`` (0 if none yet)."""
        value = await self.session.scalar(
            select(func.max(RunEvent.seq)).where(RunEvent.run_id == run_id)
        )
        return int(value or 0)

    async def append(
        self,
        *,
        run_id: uuid.UUID,
        org_id: uuid.UUID,
        event_type: str,
        message: str | None = None,
        data: dict[str, Any] | None = None,
        seq: int | None = None,
    ) -> RunEvent:
        """Append one trace event and return it (flushed, NOT committed).

        ``seq`` is assigned as ``max(seq)+1`` for the run when not supplied. Safe
        without locking because a run has a single writer (its runner)."""
        if seq is None:
            seq = await self.latest_seq(run_id) + 1
        event = RunEvent(
            run_id=run_id,
            org_id=org_id,
            seq=seq,
            event_type=event_type,
            message=message,
            data=data,
        )
        self.session.add(event)
        await self.session.flush()
        return event

    async def list_after(
        self, run_id: uuid.UUID, after_seq: int, *, limit: int = 500
    ) -> list[RunEvent]:
        """Return events for ``run_id`` with ``seq > after_seq``, in ``seq`` order.

        The exact SSE tail query (served by the ``ix_run_events_run_id_seq``
        composite index). ``limit`` bounds a single poll's batch so a burst of
        reasoning lines can't build an unbounded frame."""
        stmt = (
            select(RunEvent)
            .where(RunEvent.run_id == run_id, RunEvent.seq > after_seq)
            .order_by(RunEvent.seq.asc())
            .limit(limit)
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def list_for_run(
        self, run_id: uuid.UUID, *, limit: int = 2000
    ) -> list[RunEvent]:
        """Return the full trace for ``run_id`` in ``seq`` order (bounded replay)."""
        stmt = (
            select(RunEvent)
            .where(RunEvent.run_id == run_id)
            .order_by(RunEvent.seq.asc())
            .limit(limit)
        )
        return list((await self.session.execute(stmt)).scalars().all())
