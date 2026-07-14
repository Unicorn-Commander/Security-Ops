"""ScheduledScan — a cron-triggered scan configuration.

Each row defines a recurring scan: a cron expression, target set, optional
engine/model overrides, and an active flag. The scheduler service evaluates
the cron expression and creates runs when due.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import Boolean, ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

_JSONB = JSON().with_variant(JSONB(), "postgresql")


class ScheduledScan(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scheduled_scans"

    org_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("organizations.id"), nullable=False, index=True
    )
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(), ForeignKey("engagements.id"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    cron_expression: Mapped[str] = mapped_column(
        String(128), nullable=False, comment="Standard 5-field cron (no seconds)"
    )
    targets: Mapped[list] = mapped_column(
        _JSONB, nullable=False, comment="List of target values to scan"
    )
    engine: Mapped[str | None] = mapped_column(
        String(64), nullable=True, comment="Engine override (e.g. 'nuclei', 'prowler')"
    )
    model_profile: Mapped[str | None] = mapped_column(
        String(255), nullable=True, comment="Model profile override"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa.true()
    )
    last_run_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    next_run_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    org: Mapped["Organization"] = relationship("Organization")  # noqa: F821

    def __repr__(self) -> str:
        return (
            f"<ScheduledScan id={self.id} name={self.name!r} "
            f"cron={self.cron_expression!r} active={self.is_active}>"
        )
