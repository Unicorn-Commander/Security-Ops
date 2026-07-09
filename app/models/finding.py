"""Finding — a single vulnerability produced by a run (populated by the Phase 2
runner). Carries the evidence/PoC the client-facing report and the Brigade
hand-off need. ``verified_by`` records the model/profile that confirmed it in the
hybrid sweep+verify flow (spec §7); ``handoff_ref`` links a Brigade ticket/PR.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:  # pragma: no cover
    from app.models.run import Run

_JSONB = JSON().with_variant(JSONB(), "postgresql")


class FindingSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, enum.Enum):
    NEW = "NEW"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    HANDED_OFF = "HANDED_OFF"
    REMEDIATED = "REMEDIATED"


def _enum(enum_cls: type[enum.Enum], name: str) -> sa.Enum:
    return sa.Enum(enum_cls, name=name, values_callable=lambda obj: [e.value for e in obj])


class Finding(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    run_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("runs.id"), nullable=False, index=True
    )
    # Denormalized for report scoping / RLS (spec §5).
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("engagements.id"), nullable=False
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("organizations.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        _enum(FindingSeverity, "finding_severity"), nullable=False
    )
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(_JSONB, nullable=True)
    poc: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Model/profile that confirmed the finding (hybrid verify).
    verified_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"),
        nullable=False,
        default=FindingStatus.NEW,
        server_default=FindingStatus.NEW.value,
    )
    # Brigade ticket / PR id once handed off.
    handoff_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    closure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    closed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    run: Mapped["Run"] = relationship("Run", back_populates="findings")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Finding id={self.id} severity={getattr(self.severity, 'value', self.severity)} "
            f"title={self.title!r}>"
        )
