"""Campaign API routes — multi-step autonomous pentest (prototype, disabled by default).

All campaign routes are gated behind ``settings.campaigns_enabled``. When
disabled, every endpoint returns 501 Not Implemented. Every run launch within a
campaign goes through the same gate-enforced path as a manual run.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from app.api.deps import DbSession, EntitledUser
from app.core.config import settings
from app.core.errors import NotFoundError, ValidationAppError
from app.repositories.campaigns import CampaignRepository
from app.schemas.campaign import (
    CampaignAdvance,
    CampaignAdvanceResult,
    CampaignCreate,
    CampaignList,
    CampaignRead,
    CampaignRunRead,
)
from app.services.campaigns import activate_campaign, advance_campaign, create_campaign

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


def _campaigns_enabled() -> None:
    if not settings.campaigns_enabled:
        raise ValidationAppError(
            "campaigns are disabled (set SECOPS_CAMPAIGNS_ENABLED=true)",
            detail={"feature": "campaigns"},
        )


@router.post("", response_model=CampaignRead, status_code=201)
async def create_campaign_route(
    data: CampaignCreate,
    session: DbSession,
    actor: EntitledUser,
) -> CampaignRead:
    _campaigns_enabled()
    campaign = await create_campaign(
        session,
        engagement_id=data.engagement_id,
        name=data.name,
        actor=actor,
        description=data.description,
        max_runs=data.max_runs,
        max_total_cost_usd=data.max_total_cost_usd,
        max_duration_hours=data.max_duration_hours,
        approval_required_phases=data.approval_required_phases,
        budget_warning_pct=data.budget_warning_pct,
        phase_engines=data.phase_engines,
    )
    return CampaignRead.model_validate(campaign)


@router.get("", response_model=CampaignList)
async def list_campaigns_route(
    session: DbSession,
    actor: EntitledUser,
    org_id: uuid.UUID | None = None,
    engagement_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> CampaignList:
    _campaigns_enabled()
    repo = CampaignRepository(session)
    if engagement_id:
        items = await repo.list_for_engagement(engagement_id, limit=limit, offset=offset)
    else:
        caller_org = getattr(actor, "org_id", None)
        items = await repo.list_for_org(caller_org or org_id, limit=limit, offset=offset) if (caller_org or org_id) else []
    return CampaignList(
        items=[CampaignRead.model_validate(c) for c in items],
        total=len(items),
    )


@router.get("/{campaign_id}", response_model=CampaignRead)
async def get_campaign_route(
    campaign_id: uuid.UUID,
    session: DbSession,
    actor: EntitledUser,
) -> CampaignRead:
    _campaigns_enabled()
    repo = CampaignRepository(session)
    campaign = await repo.get(campaign_id)
    if campaign is None:
        raise NotFoundError("campaign not found")
    return CampaignRead.model_validate(campaign)


@router.post("/{campaign_id}/activate", response_model=CampaignRead)
async def activate_campaign_route(
    campaign_id: uuid.UUID,
    session: DbSession,
    actor: EntitledUser,
) -> CampaignRead:
    _campaigns_enabled()
    campaign = await activate_campaign(session, campaign_id, actor=actor)
    return CampaignRead.model_validate(campaign)


@router.post("/{campaign_id}/advance", response_model=CampaignAdvanceResult)
async def advance_campaign_route(
    campaign_id: uuid.UUID,
    data: CampaignAdvance,
    session: DbSession,
    actor: EntitledUser,
) -> CampaignAdvanceResult:
    _campaigns_enabled()
    result = await advance_campaign(
        session,
        campaign_id,
        actor=actor,
        action=data.action,
        resume_phase=data.resume_phase,
        note=data.note,
    )
    return CampaignAdvanceResult(
        campaign=CampaignRead.model_validate(result["campaign"]),
        created_run=CampaignRunRead.model_validate(result["created_run"]) if result.get("created_run") else None,
        action_taken=result.get("action_taken", "unknown"),
        message=result.get("message", ""),
        budget_remaining_pct=result.get("budget_remaining_pct"),
    )


@router.get("/{campaign_id}/runs", response_model=list[CampaignRunRead])
async def list_campaign_runs_route(
    campaign_id: uuid.UUID,
    session: DbSession,
    actor: EntitledUser,
) -> list[CampaignRunRead]:
    _campaigns_enabled()
    from app.repositories.campaign_runs import CampaignRunRepository

    repo = CampaignRunRepository(session)
    runs = await repo.list_for_campaign(campaign_id)
    return [CampaignRunRead.model_validate(r) for r in runs]
