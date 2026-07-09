"""RunEvent — the append-only, per-run live activity stream (SSE step log).

Each row is one step in a run's life: dispatched, started, engine-spawned, a line
of agent reasoning, a finding recorded, a verify verdict, terminal. The console's
``GET /runs/{id}/events`` SSE endpoint replays these in ``seq`` order and then
tails newly-appended rows, so an operator watches a scan think in real time.

Design notes:

* **Append-only** (like :class:`~app.models.audit.AuditEvent`): ``UUIDMixin`` id,
  a single ``created_at`` (DB-defaulted), and NO ``updated_at`` — a row is never
  mutated. This is an operator-facing *trace*, NOT the tamper-evident audit log:
  it carries no hash chain and is intentionally cheap to write.
* ``org_id`` is denormalized (like ``runs``/``findings``) so the same fail-closed
  RLS ``org_isolation`` policy applies (migration ``0012``): a run's trace is
  recon-sensitive and must never cross tenants.
* ``run_id`` is a plain indexed UUID with **no FK** (mirrors ``audit_events``) —
  the trace survives independently and there is no delete-ordering coupling.
* ``event_type`` is a plain ``String`` (not a DB enum), exactly like ``Run.engine``:
  new event kinds need no migration. Canonical values live in
  :class:`RunEventType` for producers/consumers, but the column accepts any str.
* ``seq`` is a per-run monotonic counter assigned by the **single writer** of a
  run (the runner process), so it needs no DB sequence and gives the SSE client a
  stable ``Last-Event-ID`` cursor for resumption after a dropped connection.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import JSON, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin

_JSONB = JSON().with_variant(JSONB(), "postgresql")


class RunEventType(str, enum.Enum):
    """Canonical event kinds. The column is a free string (extensible without a
    migration); these are the values the runner emits and the console renders."""

    QUEUED = "queued"           # gate cleared → run created/dispatched (PENDING)
    RUNNING = "running"         # runner picked it up → RUNNING
    ENGINE_SPAWNED = "engine_spawned"  # scanner subprocess launched (pid/model)
    REASONING = "reasoning"     # a line of live agent/scanner output (strix trace)
    PHASE = "phase"             # a coarse phase transition (recon/exploit/verify…)
    FINDING = "finding"         # a finding was recorded mid-run
    VERIFY = "verify"           # a verify-pass verdict
    COMPLETED = "completed"     # terminal: succeeded
    FAILED = "failed"           # terminal: failed/errored
    STOPPED = "stopped"         # terminal: operator/emergency stop

    @classmethod
    def is_terminal(cls, value: object) -> bool:
        raw = getattr(value, "value", value)
        return raw in (cls.COMPLETED.value, cls.FAILED.value, cls.STOPPED.value)


class RunEvent(UUIDMixin, Base):
    """One append-only step in a run's live trace (no ``updated_at`` — immutable)."""

    __tablename__ = "run_events"

    # Plain indexed UUID, NO FK (mirrors audit_events): the trace stands alone.
    run_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid(), nullable=False, index=True)
    # Denormalized for the RLS org_isolation policy (migration 0012).
    org_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid(), nullable=False, index=True)

    # Per-run monotonic cursor (single-writer assigned). The client resumes from
    # the last seq it saw via the SSE ``Last-Event-ID`` header / ``?after=``.
    seq: Mapped[int] = mapped_column(Integer, nullable=False)

    # Free string (not a DB enum) so new kinds need no migration — see RunEventType.
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    data: Mapped[dict | None] = mapped_column(_JSONB, nullable=True)

    # Append-only: created_at only, DB-defaulted; no TimestampMixin / updated_at.
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        # The SSE tail query is exactly WHERE run_id = ? AND seq > ? ORDER BY seq.
        sa.Index("ix_run_events_run_id_seq", "run_id", "seq"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RunEvent run={self.run_id} seq={self.seq} type={self.event_type!r}>"
