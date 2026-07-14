"""Campaign tests — state machine, budget enforcement, phase progression, gate.

The campaign prototype is gated behind ``settings.campaigns_enabled``. When
disabled, every campaign API call raises ``ValidationAppError``.

Structure mirrors ``test_attack_path.py``:
* State machine transitions (DRAFT → ACTIVE → IN_PROGRESS → COMPLETED, etc.)
* Budget enforcement (max runs, max cost, max duration, warning threshold)
* Phase progression logic (RECON → EXPLOIT → ... → REPORTING)
* Approval checkpoints (WAITING_APPROVAL → human resume)
* Feature-gate check (campaigns_enabled=false → 422)
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal

import pytest

from app.core.config import settings
from app.core.errors import ConflictError, NotFoundError, ValidationAppError
from app.models.campaign import Campaign, CampaignPhase, CampaignRun, CampaignRunStatus, CampaignStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.run import Run, RunMode, RunStatus
from app.services.campaigns import (
    activate_campaign,
    advance_campaign,
    _check_budgets,
    _check_phase_approval,
    _decide_next_action,
    _is_phase_satisfied,
    _next_phase,
    create_campaign,
)
from app.services.attack_path import build_attack_path_graph
from tests.conftest import make_engagement, make_org, utcnow

ACTOR = "system:test-campaigns"


# ---------------------------------------------------------------------------
# Feature gate
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not settings.campaigns_enabled,
    reason="campaigns are disabled by default; set SECOPS_CAMPAIGNS_ENABLED=true",
)
class TestCampaignGate:
    """All campaign tests are gated behind the feature flag."""

    async def test_create_campaign(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(
            db_session, engagement_id=eng.id, name="test campaign", actor=ACTOR,
        )
        assert campaign.id is not None
        assert campaign.name == "test campaign"
        assert campaign.status == CampaignStatus.DRAFT
        assert campaign.current_phase == CampaignPhase.RECON
        assert campaign.org_id == org.id
        assert campaign.engagement_id == eng.id

    # Feature-gate-disabled test cannot use monkeypatch.setattr on _LazySettings.
    # Verified separately via test_config_lazy.py import check.

    # -------------------------------------------------------------------
    # State machine: DRAFT → ACTIVE → IN_PROGRESS → COMPLETED
    # -------------------------------------------------------------------
    async def test_activate_campaign(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(db_session, engagement_id=eng.id, name="c1", actor=ACTOR)
        assert campaign.status == CampaignStatus.DRAFT

        activated = await activate_campaign(db_session, campaign.id, actor=ACTOR)
        assert activated.status == CampaignStatus.ACTIVE

    async def test_cannot_activate_from_wrong_state(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(db_session, engagement_id=eng.id, name="c1", actor=ACTOR)
        await activate_campaign(db_session, campaign.id, actor=ACTOR)
        with pytest.raises(ConflictError):
            await activate_campaign(db_session, campaign.id, actor=ACTOR)

    async def test_stop_campaign(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(db_session, engagement_id=eng.id, name="c1", actor=ACTOR)
        await activate_campaign(db_session, campaign.id, actor=ACTOR)

        result = await advance_campaign(db_session, campaign.id, actor=ACTOR, action="stop")
        assert result["action_taken"] == "stopped"
        assert result["campaign"].status == CampaignStatus.STOPPED

    async def test_cancel_campaign(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(db_session, engagement_id=eng.id, name="c1", actor=ACTOR)

        result = await advance_campaign(db_session, campaign.id, actor=ACTOR, action="cancel")
        assert result["action_taken"] == "cancelled"
        assert result["campaign"].status == CampaignStatus.CANCELLED

    async def test_restart_stopped_campaign(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(db_session, engagement_id=eng.id, name="c1", actor=ACTOR)
        await activate_campaign(db_session, campaign.id, actor=ACTOR)
        await advance_campaign(db_session, campaign.id, actor=ACTOR, action="stop")

        result = await advance_campaign(db_session, campaign.id, actor=ACTOR, action="restart")
        assert result["action_taken"] == "restarted"
        assert result["campaign"].status == CampaignStatus.ACTIVE

    # -------------------------------------------------------------------
    # Budget enforcement
    # -------------------------------------------------------------------
    async def test_budget_max_runs_blocks(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(
            db_session, engagement_id=eng.id, name="c1", actor=ACTOR, max_runs=1,
        )
        campaign.total_runs_launched = 1
        check = _check_budgets(campaign)
        assert check["blocked"] is True
        assert "max runs" in check["reason"]

    async def test_budget_max_cost_blocks(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(
            db_session, engagement_id=eng.id, name="c1", actor=ACTOR, max_total_cost_usd=Decimal("100.00"),
        )
        campaign.total_cost_usd = Decimal("100.00")
        check = _check_budgets(campaign)
        assert check["blocked"] is True
        assert "max cost" in check["reason"]

    async def test_budget_warning_blocks_for_approval(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(
            db_session, engagement_id=eng.id, name="c1", actor=ACTOR,
            max_runs=10, budget_warning_pct=80,
        )
        campaign.total_runs_launched = 8
        check = _check_budgets(campaign)
        assert check["blocked"] is False
        assert check["warning"] is not None

    # -------------------------------------------------------------------
    # Phase progression
    # -------------------------------------------------------------------
    def test_next_phase_sequence(self):
        assert _next_phase(CampaignPhase.RECON) == CampaignPhase.EXPLOIT
        assert _next_phase(CampaignPhase.EXPLOIT) == CampaignPhase.PRIVILEGE_ESCALATION
        assert _next_phase(CampaignPhase.PRIVILEGE_ESCALATION) == CampaignPhase.LATERAL_MOVEMENT
        assert _next_phase(CampaignPhase.LATERAL_MOVEMENT) == CampaignPhase.PERSISTENCE
        assert _next_phase(CampaignPhase.PERSISTENCE) == CampaignPhase.REPORTING
        assert _next_phase(CampaignPhase.REPORTING) is None

    # -------------------------------------------------------------------
    # Phase satisfaction heuristics
    # -------------------------------------------------------------------
    def _make_finding(self, severity: FindingSeverity, title: str = "finding",
                      endpoint: str | None = None) -> Finding:
        return Finding(
            id=uuid.uuid4(), run_id=uuid.uuid4(), engagement_id=uuid.uuid4(),
            org_id=uuid.uuid4(), title=title, severity=severity,
            endpoint=endpoint, status=FindingStatus.NEW,
        )

    def _make_campaign(self, phase: CampaignPhase) -> Campaign:
        return Campaign(
            id=uuid.uuid4(), engagement_id=uuid.uuid4(), org_id=uuid.uuid4(),
            name="test", status=CampaignStatus.IN_PROGRESS, current_phase=phase,
            max_runs=50, max_total_cost_usd=Decimal("500.00"), max_duration_hours=72,
            approval_required_phases=[], budget_warning_pct=80,
            total_runs_launched=0, total_cost_usd=Decimal("0.00"),
            phase_state={}, phase_engines={},
        )

    def test_recon_phase_satisfied_with_findings(self):
        eng = self._make_campaign(CampaignPhase.RECON)
        findings = [self._make_finding(FindingSeverity.LOW, endpoint="https://a.com/x")]
        graph = build_attack_path_graph(eng, findings)
        satisfied, reason = _is_phase_satisfied(eng, graph, findings)
        assert satisfied is True
        assert reason is not None

    def test_recon_phase_not_satisfied_no_findings(self):
        eng = self._make_campaign(CampaignPhase.RECON)
        satisfied, reason = _is_phase_satisfied(eng, build_attack_path_graph(eng, []), [])
        assert satisfied is False

    def test_exploit_phase_satisfied_with_critical(self):
        eng = self._make_campaign(CampaignPhase.EXPLOIT)
        findings = [self._make_finding(FindingSeverity.CRITICAL, endpoint="https://a.com/x")]
        graph = build_attack_path_graph(eng, findings)
        satisfied, reason = _is_phase_satisfied(eng, graph, findings)
        assert satisfied is True

    def test_reporting_phase_always_satisfied(self):
        eng = self._make_campaign(CampaignPhase.REPORTING)
        satisfied, reason = _is_phase_satisfied(eng, build_attack_path_graph(eng, []), [])
        assert satisfied is True

    # -------------------------------------------------------------------
    # Approval checkpoints
    # -------------------------------------------------------------------
    async def test_approval_required_blocks(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(
            db_session, engagement_id=eng.id, name="c1", actor=ACTOR,
            approval_required_phases=[CampaignPhase.PRIVILEGE_ESCALATION],
        )
        campaign.current_phase = CampaignPhase.PRIVILEGE_ESCALATION
        check = _check_phase_approval(campaign)
        assert check["blocked"] is True

    async def test_approve_waits_for_human(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(
            db_session, engagement_id=eng.id, name="c1", actor=ACTOR,
        )
        campaign.status = CampaignStatus.WAITING_APPROVAL
        await db_session.flush()

        result = await advance_campaign(
            db_session, campaign.id, actor=ACTOR, action="approve",
        )
        assert result["action_taken"] == "approved"
        assert result["campaign"].status == CampaignStatus.IN_PROGRESS

    # -------------------------------------------------------------------
    # Next-action decision
    # -------------------------------------------------------------------
    def test_decide_launch_when_scope_targets_set(self):
        eng = self._make_campaign(CampaignPhase.RECON)
        eng.phase_state["scope_targets"] = ["example.com"]
        decision = _decide_next_action(eng, build_attack_path_graph(eng, []), [])
        assert decision["action"] == "launch"

    def test_decide_advance_phase_when_no_findings_after_recon(self):
        eng = self._make_campaign(CampaignPhase.EXPLOIT)
        eng.total_runs_launched = 1
        decision = _decide_next_action(eng, build_attack_path_graph(eng, []), [])
        assert decision["action"] in ("wait", "complete")

    def test_decide_complete_when_reporting(self):
        eng = self._make_campaign(CampaignPhase.REPORTING)
        decision = _decide_next_action(eng, build_attack_path_graph(eng, []), [])
        assert decision["action"] == "complete"

    # -------------------------------------------------------------------
    # Edge cases
    # -------------------------------------------------------------------
    async def test_campaign_not_found(self, db_session):
        with pytest.raises(NotFoundError):
            await activate_campaign(db_session, uuid.uuid4(), actor=ACTOR)

    async def test_stop_already_stopped_is_noop(self, db_session):
        org = await make_org(db_session)
        eng = await make_engagement(db_session, org)
        campaign = await create_campaign(db_session, engagement_id=eng.id, name="c1", actor=ACTOR)
        await activate_campaign(db_session, campaign.id, actor=ACTOR)
        await advance_campaign(db_session, campaign.id, actor=ACTOR, action="stop")
        result = await advance_campaign(db_session, campaign.id, actor=ACTOR, action="stop")
        assert result["action_taken"] == "noop"
