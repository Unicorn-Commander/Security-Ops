"""Campaign — a bounded, multi-step autonomous pentest plan (prototype, disabled by default).

A campaign groups multiple related runs under a shared strategy and budget. It is
driven by the attack-path graph: after each run, the campaign evaluator looks at
new findings to decide what to probe next (recon → exploit → pivot → persist →
report). Every step re-verifies authorization at action time — a campaign is NEVER
trusted to self-authorize.

The entire campaign feature is gated behind ``settings.campaigns_enabled``
(default ``False``). When disabled, no campaign can be created or progressed.

Campaign state machine::

    DRAFT ──┬─→ ACTIVE ──→ IN_PROGRESS ──→ COMPLETED
             │                                FAILED
             │                                STOPPED
             │                                EXPIRED
             │              (from DRAFT or STOPPED, via restart)
             └────────────→ CANCELLED

Phase model — each campaign follows a bounded phase sequence. A phase is
auto-advanced when its exit criteria are met or when the attack-path evaluator
deems the next phase actionable::

    RECON → EXPLOIT → PRIVILEGE_ESCALATION → LATERAL_MOVEMENT → PERSISTENCE → REPORTING

Per-run status within a campaign::

    PENDING → IN_PROGRESS → COMPLETED / FAILED / SKIPPED

Budget model: every campaign carries a budget cap that stops the campaign when
exceeded (before the next run is launched, never mid-run)::

  - max_runs: maximum individual runs the campaign may launch (default 50)
  - max_total_cost_usd: cumulative cost ceiling across all runs (default $500)
  - max_duration_hours: wall-clock time from first run start (default 72h)

Approval checkpoints: certain phase boundaries or budget thresholds BLOCK the
campaign and transition it to ``WAITING_APPROVAL`` until a human resumes it::

  - approval_required: which phases require a human nod before the campaign
    proceeds (e.g. ["privilege_escalation", "lateral_movement"])
  - budget_warning_pct: when spent >= this % of any budget, block for approval
    (default 80, meaning at 80% spend the campaign pauses for human review)
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import ForeignKey, Integer, JSON, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.engagement import Engagement
    from app.models.run import Run

_JSONB = JSON().with_variant(JSONB(), "postgresql")


class CampaignStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    IN_PROGRESS = "IN_PROGRESS"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class CampaignPhase(str, enum.Enum):
    RECON = "RECON"
    EXPLOIT = "EXPLOIT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PERSISTENCE = "PERSISTENCE"
    REPORTING = "REPORTING"


class CampaignRunStatus(str, enum.Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


def _enum(enum_cls: type[enum.Enum], name: str) -> sa.Enum:
    return sa.Enum(enum_cls, name=name, values_callable=lambda obj: [e.value for e in obj])


class Campaign(UUIDMixin, TimestampMixin, Base):
    """A bounded multi-step autonomous pentest plan.

    Gates:
    - ``settings.campaigns_enabled`` must be ``True`` for any CREATE or PROGRESS.
    - Every run within the campaign re-checks ``app.authz.gate.enforce_scope``.
    - Budgets are enforced before each run launch (never mid-run).

    DISABLED BY DEFAULT. The feature flag is deliberately explicit so no
    campaign runs autonomously without operator intent.
    """

    __tablename__ = "campaigns"

    engagement_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("engagements.id"), nullable=False, index=True
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("organizations.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[CampaignStatus] = mapped_column(
        _enum(CampaignStatus, "campaign_status"),
        nullable=False,
        default=CampaignStatus.DRAFT,
        server_default=CampaignStatus.DRAFT.value,
    )
    current_phase: Mapped[CampaignPhase] = mapped_column(
        _enum(CampaignPhase, "campaign_phase"),
        nullable=False,
        default=CampaignPhase.RECON,
        server_default=CampaignPhase.RECON.value,
    )

    # -- Budget enforcement --------------------------------------------------
    max_runs: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50, server_default="50"
    )
    max_total_cost_usd: Mapped[Decimal] = mapped_column(
        Numeric(14, 6), nullable=False, default=Decimal("500.00"),
        server_default="500.00",
    )
    max_duration_hours: Mapped[int] = mapped_column(
        Integer, nullable=False, default=72, server_default="72"
    )

    # -- Approval checkpoints ------------------------------------------------
    # JSON list of phase values that require human approval before proceeding.
    # Example: ["privilege_escalation", "lateral_movement"]
    approval_required_phases: Mapped[list] = mapped_column(
        _JSONB, nullable=False, default=list, server_default="'[]'::jsonb"
    )
    # Percentage of ANY budget cap that triggers a WAITING_APPROVAL block.
    budget_warning_pct: Mapped[int] = mapped_column(
        Integer, nullable=False, default=80, server_default="80"
    )

    # -- Accumulators --------------------------------------------------------
    total_runs_launched: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    total_cost_usd: Mapped[Decimal] = mapped_column(
        Numeric(14, 6), nullable=False, default=Decimal("0.00"),
        server_default="0.00",
    )
    # Wall-clock: set when first run transitions to IN_PROGRESS.
    first_run_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # -- Phase-specific state (JSON) -----------------------------------------
    # Tracks per-phase context: targets discovered, credentials found, access
    # levels achieved, etc. Evaluated by the campaign orchestrator to decide
    # the next run.
    phase_state: Mapped[dict] = mapped_column(
        _JSONB, nullable=False, default=dict, server_default="'{}'::jsonb"
    )

    # Set when a human resumes a WAITING_APPROVAL campaign.
    resumed_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    resumed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    # -- Engine targeting ----------------------------------------------------
    # Which engines to use at each phase (overrides the engagement default).
    # Example: {"recon": ["naabu", "nuclei"], "exploit": ["strix"], ...}
    phase_engines: Mapped[dict] = mapped_column(
        _JSONB, nullable=False, default=dict, server_default="'{}'::jsonb"
    )

    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="campaigns")
    runs: Mapped[list["CampaignRun"]] = relationship(
        "CampaignRun", back_populates="campaign", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Campaign id={self.id} name={self.name!r} "
            f"status={getattr(self.status, 'value', self.status)} "
            f"phase={getattr(self.current_phase, 'value', self.current_phase)}>"
        )


class CampaignRun(UUIDMixin, TimestampMixin, Base):
    """A single run within a campaign. Links the campaign to its concrete Run.

    Each CampaignRun is an orchestrated scan step. The campaign evaluator
    creates one, the engine executes it, and the result feeds back into the
    attack-path evaluator for the next step decision.
    """

    __tablename__ = "campaign_runs"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("campaigns.id"), nullable=False, index=True
    )
    # The concrete Run row (created by services.runs.start_run after gate check).
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(), ForeignKey("runs.id"), nullable=True
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("organizations.id"), nullable=False
    )

    # Which campaign phase this run belongs to.
    phase: Mapped[CampaignPhase] = mapped_column(
        _enum(CampaignPhase, "campaign_phase"), nullable=False
    )
    status: Mapped[CampaignRunStatus] = mapped_column(
        _enum(CampaignRunStatus, "campaign_run_status"),
        nullable=False,
        default=CampaignRunStatus.PENDING,
        server_default=CampaignRunStatus.PENDING.value,
    )

    # Which scan engine was dispatched.
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    # The concrete gate-checked target(s) for this run.
    targets: Mapped[list] = mapped_column(_JSONB, nullable=False)
    # Why this run was created (e.g. "follow-on from finding X on host Y").
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(14, 6), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="runs")
    run: Mapped["Run | None"] = relationship("Run", foreign_keys=[run_id])

    def __repr__(self) -> str:
        return (
            f"<CampaignRun id={self.id} campaign={self.campaign_id} "
            f"phase={getattr(self.phase, 'value', self.phase)} "
            f"status={getattr(self.status, 'value', self.status)}>"
        )
