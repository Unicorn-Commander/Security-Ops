"""RunQueueEntry — the dispatch hand-off from the API to the isolated runner.

When ``settings.run_dispatch_mode == "queue"``, ``app.services.runs.start_run``
inserts ONE row here **in the same transaction** as the gate-cleared ``PENDING``
run (so dispatch is atomic and durable — an API crash between commit and launch
can never lose a run). The dedicated ``secops-runner`` sidecar then claims the
oldest unclaimed row (``FOR UPDATE SKIP LOCKED``) and executes it.

Isolation posture: this table is **deliberately NOT row-level-security policed**
(like ``organizations``). It carries only routing metadata — the run/org/engagement
ids and the run's scope parameters — never tenant-sensitive findings or evidence.
The runner reads it as ``secops_app`` (NOBYPASSRLS) with no org GUC set; that role
sees these rows precisely because the table is unpoliced. Every subsequent query
against the real ``runs``/``findings``/``engagements`` rows is made through
``execute_run`` with the org GUC bound, so those stay under RLS. Keeping the queue
unpoliced avoids handing the runner a BYPASSRLS role.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class RunQueueEntry(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "run_queue"

    # One queue entry per run (a re-enqueue of the same run is a conflict, not a dup).
    run_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("runs.id"), nullable=False, unique=True, index=True
    )
    # Threaded to the runner so execute_run can bind the org GUC under RLS without a
    # request context (the runner has none of its own).
    org_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid(), nullable=False)
    engagement_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid(), nullable=False)
    # Run parameters carried through to execute_run.
    scope_mode: Mapped[str | None] = mapped_column(Text, nullable=True)
    diff_base: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Claim bookkeeping: NULL claimed_at == available. Set atomically on claim.
    claimed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True, index=True
    )
    claimed_by: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        state = "claimed" if self.claimed_at else "available"
        return f"<RunQueueEntry run={self.run_id} {state}>"
