"""Campaign schemas — typed contracts for the campaign API surface.

Designed as a prototype: gated behind ``settings.campaigns_enabled``, disabled
by default. Every create/progress call re-verifies authorization.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, Field

from app.models.campaign import CampaignPhase, CampaignRunStatus, CampaignStatus


class CampaignCreate(BaseModel):
    """Request body for ``POST /campaigns`` (gated by ``campaigns_enabled``)."""

    engagement_id: uuid.UUID
    name: str = Field(min_length=1, max_length=256)
    description: str | None = None

    # Budget caps.
    max_runs: int = Field(default=50, ge=1, le=500)
    max_total_cost_usd: Decimal = Field(default=Decimal("500.00"), ge=0)
    max_duration_hours: int = Field(default=72, ge=1, le=720)

    # Approval checkpoints.
    approval_required_phases: list[CampaignPhase] = Field(default_factory=list)
    budget_warning_pct: int = Field(default=80, ge=0, le=100)

    # Engine targeting per phase.
    phase_engines: dict[CampaignPhase, list[str]] = Field(default_factory=dict)


class CampaignRead(BaseModel):
    """Full campaign view (response body)."""

    id: uuid.UUID
    engagement_id: uuid.UUID
    org_id: uuid.UUID
    name: str
    description: str | None
    status: CampaignStatus
    current_phase: CampaignPhase

    max_runs: int
    max_total_cost_usd: Decimal
    max_duration_hours: int
    approval_required_phases: list
    budget_warning_pct: int

    total_runs_launched: int
    total_cost_usd: Decimal
    first_run_at: datetime | None
    started_at: datetime | None
    ended_at: datetime | None
    error: str | None

    phase_state: dict
    phase_engines: dict

    resumed_by: str | None
    resumed_at: datetime | None

    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CampaignRunRead(BaseModel):
    """One campaign run within a campaign."""

    id: uuid.UUID
    campaign_id: uuid.UUID
    run_id: uuid.UUID | None
    phase: CampaignPhase
    status: CampaignRunStatus
    engine: str
    targets: list
    rationale: str | None
    started_at: datetime | None
    ended_at: datetime | None
    cost_usd: Decimal | None
    error: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CampaignList(BaseModel):
    items: list[CampaignRead]
    total: int


class CampaignAdvance(BaseModel):
    """Request to advance a campaign: either auto-evaluate or explicit step."""

    action: Literal["evaluate", "approve", "restart", "stop", "cancel"] = "evaluate"
    # When action=approve, optionally override the phase to continue from.
    resume_phase: CampaignPhase | None = None
    # Optional human note recorded in audit.
    note: str | None = None


class CampaignAdvanceResult(BaseModel):
    campaign: CampaignRead
    created_run: CampaignRunRead | None = None
    action_taken: str
    message: str
    budget_remaining_pct: int | None = None
