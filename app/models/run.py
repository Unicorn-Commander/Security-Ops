"""Run — a single scan execution against an engagement's authorized targets.

A run row is created ONLY after ``app.authz.gate.enforce_scope`` passes for every
concrete target in ``targets`` (enforced server-side in
``app.services.runs.start_run``). Phase 2 populates strix_run_id / cost / usage /
report_path via the subprocess runner; Phase 1 leaves a run PENDING.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import ForeignKey, JSON, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:  # pragma: no cover
    from app.models.engagement import Engagement
    from app.models.finding import Finding

_JSONB = JSON().with_variant(JSONB(), "postgresql")


class RunStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    # Gate denied the run at creation time; no scan touched any target.
    DENIED = "DENIED"


class RunMode(str, enum.Enum):
    QUICK = "QUICK"
    STANDARD = "STANDARD"
    DEEP = "DEEP"


def _enum(enum_cls: type[enum.Enum], name: str) -> sa.Enum:
    return sa.Enum(
        enum_cls, name=name, values_callable=lambda obj: [e.value for e in obj]
    )


class Run(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "runs"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("engagements.id"), nullable=False, index=True
    )
    # Denormalized for RLS (spec §5) — filterable without a join.
    org_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("organizations.id"), nullable=False
    )
    # Strix's own run id (set in Phase 2).
    strix_run_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Which scan engine executes this run. Additive multi-engine support (spec §7
    # extension): a plain string (not an enum) so new engines need no migration.
    # ``strix`` = the autonomous offensive agent (default); ``nuclei`` = templated
    # breadth scanner. The runner dispatches on this value; both ride the SAME
    # authorization gate + attestation + findings/verify pipeline.
    engine: Mapped[str] = mapped_column(
        String(32), nullable=False, default="strix", server_default="strix"
    )
    mode: Mapped[RunMode] = mapped_column(_enum(RunMode, "run_mode"), nullable=False)
    model_profile: Mapped[str] = mapped_column(String(255), nullable=False)
    # Concrete gate-checked targets this run covers (list[str]).
    targets: Mapped[list] = mapped_column(_JSONB, nullable=False)
    status: Mapped[RunStatus] = mapped_column(
        _enum(RunStatus, "run_status"),
        nullable=False,
        default=RunStatus.PENDING,
        server_default=RunStatus.PENDING.value,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(14, 6), nullable=True)
    usage: Mapped[dict | None] = mapped_column(_JSONB, nullable=True)
    # Filesystem location of the Strix report bundle (./strix_runs/<run>/).
    report_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Optional per-run execution ceiling from the organization/engagement policy.
    max_execution_time: Mapped[int | None] = mapped_column(sa.Integer(), nullable=True)

    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="runs")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="run")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Run id={self.id} mode={getattr(self.mode, 'value', self.mode)} "
            f"status={getattr(self.status, 'value', self.status)}>"
        )
