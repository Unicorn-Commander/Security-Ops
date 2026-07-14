"""Engagement — the scope-of-engagement record the authorization gate enforces.

An engagement carries the authoritative in-scope/exclusion rules + rules-of-
engagement (intensity, allowed vuln classes, time window, concurrency) and an
emergency-stop. ``app.authz.gate.enforce_scope`` requires an engagement to be
ACTIVE, unexpired, inside its time window, and not emergency-stopped before any
target it covers may be scanned (spec §4).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Boolean, ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:  # pragma: no cover
    from app.models.campaign import Campaign
    from app.models.organization import Organization
    from app.models.run import Run

_JSONB = JSON().with_variant(JSONB(), "postgresql")


class EngagementStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    EXPIRED = "EXPIRED"


def _enum(enum_cls: type[enum.Enum], name: str) -> sa.Enum:
    return sa.Enum(enum_cls, name=name, values_callable=lambda obj: [e.value for e in obj])


class Engagement(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "engagements"

    org_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[EngagementStatus] = mapped_column(
        _enum(EngagementStatus, "engagement_status"),
        nullable=False,
        default=EngagementStatus.DRAFT,
        server_default=EngagementStatus.DRAFT.value,
    )
    # EngagementScope = {in_scope: [ScopeRule], exclusions: [ScopeRule]}.
    scope: Mapped[dict] = mapped_column(_JSONB, nullable=False)
    # RulesOfEngagement = {intensity, allowed_vuln_classes, time_window_start/end, max_concurrency}.
    rules_of_engagement: Mapped[dict] = mapped_column(_JSONB, nullable=False)
    # Hybrid discovery+verify profile (spec §7).
    model_profile: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="hybrid-local-sweep-verify",
        server_default="hybrid-local-sweep-verify",
    )
    # Principal (id/email) who created the engagement.
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    starts_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    # Engagement / time-window expiry — the gate rejects scans after this.
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    emergency_stopped: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa.false()
    )
    # Engine domain restrictions (JSONB; engine -> [glob patterns]).
    # Overrides the org-level and system-domain defaults for this engagement.
    engine_domain_restrictions: Mapped[dict | None] = mapped_column(_JSONB, nullable=True)

    org: Mapped["Organization"] = relationship("Organization", back_populates="engagements")
    runs: Mapped[list["Run"]] = relationship("Run", back_populates="engagement")
    campaigns: Mapped[list["Campaign"]] = relationship("Campaign", back_populates="engagement")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Engagement id={self.id} name={self.name!r} "
            f"status={getattr(self.status, 'value', self.status)}>"
        )
