"""FindingRemediation — 1:1 remediation tracking for a confirmed finding.

Complements the ``Finding`` model's status/closure fields with structured
remediation planning, re-verification state, and an audit trail of notes.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

_JSONB = JSON().with_variant(JSONB(), "postgresql")


class ReTestStatus(str, enum.Enum):
    PENDING = "PENDING"
    FIXED = "FIXED"
    REOPENED = "REOPENED"
    NOT_REQUIRED = "NOT_REQUIRED"


def _enum(enum_cls: type[enum.Enum], name: str) -> sa.Enum:
    return sa.Enum(enum_cls, name=name, values_callable=lambda obj: [e.value for e in obj])


class FindingRemediation(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "finding_remediations"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("findings.id"), nullable=False, unique=True, index=True
    )
    remediation_plan: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_steps: Mapped[list | None] = mapped_column(_JSONB, nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    re_test_status: Mapped[ReTestStatus] = mapped_column(
        _enum(ReTestStatus, "re_test_status"),
        nullable=False,
        default=ReTestStatus.PENDING,
        server_default=ReTestStatus.PENDING.value,
    )
    re_test_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    finding: Mapped["Finding"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        "Finding", back_populates="remediation", uselist=False
    )

    def __repr__(self) -> str:
        return (
            f"<FindingRemediation id={self.id} finding_id={self.finding_id} "
            f"re_test={getattr(self.re_test_status, 'value', self.re_test_status)}>"
        )
