"""Campaign orchestrator — bounded multi-step autonomous pentest (prototype).

This service owns the campaign lifecycle: create, advance (evaluate → launch →
check budgets → check approval gates → repeat), stop, restart, and cancel. Every
action is gated:

1. ``settings.campaigns_enabled`` must be ``True`` (disabled by default).
2. Every run launch re-checks ``app.authz.gate.enforce_scope`` at action time.
3. Budget limits and approval checkpoints are enforced BEFORE a run is created.

Design invariants:

* The orchestrator NEVER skips the authorization gate. Each run within a campaign
  is a full ``start_run`` call through ``services.runs.start_run``, which enforces
  engagement-level + scope + attestation checks.
* The orchestrator is NOT autonomous by default. It requires the feature flag AND
  the campaign status to be ``ACTIVE`` or ``IN_PROGRESS``. ``WAITING_APPROVAL``
  blocks all progress until a human resumes it.
* The attack-path graph is consulted for the next-step decision, but the graph
  itself is a pure projection of existing findings (no new state). The campaign
  adds ``phase_state`` to track context that the graph doesn't capture (e.g.
  which credentials were harvested, which access levels achieved).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.writer import record_event
from app.core.config import settings
from app.core.errors import ConflictError, NotFoundError, ValidationAppError
from app.models.audit import AuditAction
from app.models.campaign import Campaign, CampaignPhase, CampaignRun, CampaignRunStatus, CampaignStatus
from app.models.finding import FindingSeverity
from app.models.run import RunStatus
from app.repositories.campaigns import CampaignRepository
from app.repositories.engagements import EngagementRepository
from app.repositories.findings import FindingRepository
from app.services.attack_path import build_attack_path_graph

if TYPE_CHECKING:
    from app.auth.sso import AuthUser

logger = logging.getLogger("secops.services.campaigns")

# Phase ordering — the campaign advances through this sequence.
_PHASE_SEQUENCE: list[CampaignPhase] = [
    CampaignPhase.RECON,
    CampaignPhase.EXPLOIT,
    CampaignPhase.PRIVILEGE_ESCALATION,
    CampaignPhase.LATERAL_MOVEMENT,
    CampaignPhase.PERSISTENCE,
    CampaignPhase.REPORTING,
]

_TERMINAL_CAMPAIGN_STATUSES: frozenset[CampaignStatus] = frozenset({
    CampaignStatus.COMPLETED,
    CampaignStatus.FAILED,
    CampaignStatus.STOPPED,
    CampaignStatus.EXPIRED,
    CampaignStatus.CANCELLED,
})

# Engines considered valid per-phase if no explicit phase_engines override.
_DEFAULT_PHASE_ENGINES: dict[CampaignPhase, list[str]] = {
    CampaignPhase.RECON: ["naabu", "nuclei"],
    CampaignPhase.EXPLOIT: ["strix", "zap"],
    CampaignPhase.PRIVILEGE_ESCALATION: ["strix"],
    CampaignPhase.LATERAL_MOVEMENT: ["strix", "nuclei"],
    CampaignPhase.PERSISTENCE: ["gitleaks", "trivy"],
    CampaignPhase.REPORTING: [],
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _enum_value(value: object) -> object:
    return getattr(value, "value", value)


def _feature_gate() -> None:
    """Raise if the campaign feature is disabled."""
    if not settings.campaigns_enabled:
        raise ValidationAppError(
            "campaigns are disabled (set SECOPS_CAMPAIGNS_ENABLED=true)",
            detail={"feature": "campaigns"},
        )


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------
async def create_campaign(
    session: AsyncSession,
    *,
    engagement_id: uuid.UUID,
    name: str,
    actor: "AuthUser",
    description: str | None = None,
    max_runs: int = 50,
    max_total_cost_usd: Decimal = Decimal("500.00"),
    max_duration_hours: int = 72,
    approval_required_phases: list[CampaignPhase] | None = None,
    budget_warning_pct: int = 80,
    phase_engines: dict[CampaignPhase, list[str]] | None = None,
) -> Campaign:
    _feature_gate()

    engagement = await EngagementRepository(session).get(engagement_id)
    if engagement is None:
        raise NotFoundError("engagement not found")

    campaign = Campaign(
        id=uuid.uuid4(),
        engagement_id=engagement_id,
        org_id=engagement.org_id,
        name=name,
        description=description,
        status=CampaignStatus.DRAFT,
        current_phase=CampaignPhase.RECON,
        max_runs=max_runs,
        max_total_cost_usd=max_total_cost_usd,
        max_duration_hours=max_duration_hours,
        approval_required_phases=approval_required_phases or [],
        budget_warning_pct=budget_warning_pct,
        phase_engines=phase_engines or {},
    )
    session.add(campaign)
    await session.flush()

    await record_event(
        session,
        action=AuditAction.CAMPAIGN_CREATED,
        actor=actor,
        org_id=campaign.org_id,
        engagement_id=engagement_id,
        run_id=None,
        decision="created",
        reason=f"campaign {name!r} created in DRAFT",
        detail={
            "campaign_id": str(campaign.id),
            "max_runs": max_runs,
            "max_total_cost_usd": str(max_total_cost_usd),
            "max_duration_hours": max_duration_hours,
        },
    )
    await session.commit()
    return campaign


# ---------------------------------------------------------------------------
# Activate (DRAFT → ACTIVE)
# ---------------------------------------------------------------------------
async def activate_campaign(
    session: AsyncSession,
    campaign_id: uuid.UUID,
    *,
    actor: "AuthUser",
) -> Campaign:
    _feature_gate()

    campaign = await CampaignRepository(session).get(campaign_id)
    if campaign is None:
        raise NotFoundError("campaign not found")
    if campaign.status != CampaignStatus.DRAFT:
        raise ConflictError(f"campaign cannot be activated from status {campaign.status.value}")

    campaign.status = CampaignStatus.ACTIVE
    await session.flush()

    await record_event(
        session,
        action=AuditAction.CAMPAIGN_ACTIVATED,
        actor=actor,
        org_id=campaign.org_id,
        engagement_id=campaign.engagement_id,
        run_id=None,
        decision="activated",
        reason=f"campaign {campaign.name!r} activated",
        detail={"campaign_id": str(campaign.id)},
    )
    await session.commit()
    return campaign


# ---------------------------------------------------------------------------
# Advance — the main evaluation loop (one step at a time)
# ---------------------------------------------------------------------------
async def advance_campaign(
    session: AsyncSession,
    campaign_id: uuid.UUID,
    *,
    actor: "AuthUser",
    action: str = "evaluate",
    resume_phase: CampaignPhase | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Advance the campaign by one step: evaluate state → (maybe) launch run.

    ``action`` controls what happens:
    - "evaluate":  evaluate findings, decide next step, maybe launch a run.
    - "approve":   resume from WAITING_APPROVAL (optionally at a given phase).
    - "restart":   restart from ACTIVE (from STOPPED or ACTIVE).
    - "stop":      emergency-stop the campaign.
    - "cancel":    cancel the campaign (terminal).

    Returns a dict with the updated campaign, any created run, and the action
    taken description.
    """
    _feature_gate()

    campaign = await CampaignRepository(session).get(campaign_id)
    if campaign is None:
        raise NotFoundError("campaign not found")

    action = action.lower()

    if action == "stop":
        return await _stop_campaign(session, campaign, actor=actor, note=note)
    if action == "cancel":
        return await _cancel_campaign(session, campaign, actor=actor, note=note)
    if action == "restart":
        return await _restart_campaign(session, campaign, actor=actor, note=note)
    if action == "approve":
        return await _approve_campaign(session, campaign, actor=actor, resume_phase=resume_phase, note=note)
    if action == "evaluate":
        return await _evaluate_campaign(session, campaign, actor=actor)

    raise ValidationAppError(f"unknown action: {action}", detail={"action": action})


async def _evaluate_campaign(
    session: AsyncSession,
    campaign: Campaign,
    *,
    actor: "AuthUser",
) -> dict[str, Any]:
    """Core evaluation: check state → decide next move → maybe launch a run."""
    # Campaign must be ACTIVE or IN_PROGRESS to evaluate.
    if campaign.status not in (CampaignStatus.ACTIVE, CampaignStatus.IN_PROGRESS):
        return {
            "campaign": campaign,
            "created_run": None,
            "action_taken": "blocked",
            "message": f"campaign is {campaign.status.value}, not ACTIVE or IN_PROGRESS",
            "budget_remaining_pct": _budget_remaining(campaign),
        }

    # 1. Budget check — fail or warn before any new run.
    budget_check = _check_budgets(campaign)
    if budget_check["blocked"]:
        campaign.status = CampaignStatus.FAILED
        campaign.error = budget_check["reason"]
        campaign.ended_at = _utcnow()
        await session.flush()
        await _audit_decision(session, campaign, actor, "failed", budget_check["reason"])
        await session.commit()
        return {
            "campaign": campaign,
            "created_run": None,
            "action_taken": "budget_exceeded",
            "message": budget_check["reason"],
            "budget_remaining_pct": _budget_remaining(campaign),
        }
    if budget_check["warning"]:
        campaign.status = CampaignStatus.WAITING_APPROVAL
        await session.flush()
        await _audit_decision(session, campaign, actor, "waiting_approval", budget_check["warning"])
        await session.commit()
        return {
            "campaign": campaign,
            "created_run": None,
            "action_taken": "budget_warning",
            "message": budget_check["warning"],
            "budget_remaining_pct": _budget_remaining(campaign),
        }

    # 2. Phase-based approval check.
    phase_approval = _check_phase_approval(campaign)
    if phase_approval["blocked"]:
        campaign.status = CampaignStatus.WAITING_APPROVAL
        await session.flush()
        await _audit_decision(session, campaign, actor, "waiting_approval", phase_approval["reason"])
        await session.commit()
        return {
            "campaign": campaign,
            "created_run": None,
            "action_taken": "approval_required",
            "message": phase_approval["reason"],
            "budget_remaining_pct": _budget_remaining(campaign),
        }

    # 3. Evaluate findings via attack-path graph → decide next target.
    engagement = await EngagementRepository(session).get(campaign.engagement_id)
    if engagement is None:
        campaign.status = CampaignStatus.FAILED
        campaign.error = "engagement no longer exists"
        campaign.ended_at = _utcnow()
        await session.flush()
        await _audit_decision(session, campaign, actor, "failed", "engagement not found")
        await session.commit()
        return {
            "campaign": campaign,
            "created_run": None,
            "action_taken": "failed",
            "message": "engagement no longer exists",
            "budget_remaining_pct": None,
        }

    findings = await FindingRepository(session).list_for_engagement(campaign.engagement_id)
    graph = build_attack_path_graph(engagement, findings)

    decision = _decide_next_action(campaign, graph, findings)
    if decision["action"] == "complete":
        campaign.status = CampaignStatus.COMPLETED
        campaign.current_phase = CampaignPhase.REPORTING
        campaign.ended_at = _utcnow()
        await session.flush()
        await _audit_decision(session, campaign, actor, "completed", decision["reason"])
        await session.commit()
        # Update phase_state with final summary.
        campaign.phase_state["completion_summary"] = {
            "total_findings": len(findings),
            "max_severity": _enum_value(graph.summary.max_severity) if graph.summary.max_severity else None,
            "hosts_affected": graph.summary.host_count,
        }
        return {
            "campaign": campaign,
            "created_run": None,
            "action_taken": "completed",
            "message": decision["reason"],
            "budget_remaining_pct": _budget_remaining(campaign),
        }

    if decision["action"] == "wait":
        # Campaign has nothing actionable → park in ACTIVE for next poll.
        await session.commit()
        return {
            "campaign": campaign,
            "created_run": None,
            "action_taken": "waiting",
            "message": decision["reason"],
            "budget_remaining_pct": _budget_remaining(campaign),
        }

    # decision["action"] == "launch"
    created_run = await _launch_campaign_run(session, campaign, actor, decision)
    await session.commit()
    return {
        "campaign": campaign,
        "created_run": created_run,
        "action_taken": "run_launched",
        "message": decision["reason"],
        "budget_remaining_pct": _budget_remaining(campaign),
    }


# ---------------------------------------------------------------------------
# Budget checking
# ---------------------------------------------------------------------------
def _check_budgets(campaign: Campaign) -> dict[str, Any]:
    """Check all budget limits. Returns a dict with blocked/warning flags."""
    result: dict[str, Any] = {"blocked": False, "blocked_reason": None, "warning": None}

    # Hard cap: max runs.
    if campaign.total_runs_launched >= campaign.max_runs:
        return {
            "blocked": True,
            "blocked_reason": "max runs exceeded",
            "warning": None,
            "reason": f"campaign reached max runs ({campaign.max_runs})",
        }

    # Hard cap: total cost.
    if campaign.total_cost_usd >= campaign.max_total_cost_usd:
        return {
            "blocked": True,
            "blocked_reason": "max cost exceeded",
            "warning": None,
            "reason": f"campaign reached max cost (${campaign.max_total_cost_usd})",
        }

    # Hard cap: duration.
    if campaign.first_run_at is not None:
        elapsed = (_utcnow() - campaign.first_run_at).total_seconds() / 3600
        if elapsed >= campaign.max_duration_hours:
            return {
                "blocked": True,
                "blocked_reason": "max duration exceeded",
                "warning": None,
                "reason": f"campaign exceeded max duration ({campaign.max_duration_hours}h)",
            }

    # Soft cap: budget warning percentage.
    if campaign.budget_warning_pct > 0:
        run_pct = (campaign.total_runs_launched / campaign.max_runs) * 100
        cost_pct = float(campaign.total_cost_usd / campaign.max_total_cost_usd) * 100 if campaign.max_total_cost_usd > 0 else 0
        if run_pct >= campaign.budget_warning_pct or cost_pct >= campaign.budget_warning_pct:
            return {
                "blocked": False,
                "blocked_reason": None,
                "warning": f"budget threshold reached ({campaign.budget_warning_pct}%): "
                          f"runs={run_pct:.0f}% cost=${campaign.total_cost_usd:.2f}",
                "reason": None,
            }

    return result


def _budget_remaining(campaign: Campaign) -> int:
    """Return the lowest remaining budget percentage (0-100)."""
    run_pct = (campaign.total_runs_launched / campaign.max_runs) * 100 if campaign.max_runs > 0 else 100
    cost_pct = float(campaign.total_cost_usd / campaign.max_total_cost_usd) * 100 if campaign.max_total_cost_usd > 0 else 100
    pct = max(run_pct, cost_pct)
    return max(0, 100 - int(pct))


# ---------------------------------------------------------------------------
# Phase approval check
# ---------------------------------------------------------------------------
def _check_phase_approval(campaign: Campaign) -> dict[str, Any]:
    """Check if current phase requires human approval."""
    required = campaign.approval_required_phases or []
    if _enum_value(campaign.current_phase) in required:
        return {
            "blocked": True,
            "reason": f"phase {campaign.current_phase.value} requires human approval before proceeding",
        }
    return {"blocked": False, "reason": None}


# ---------------------------------------------------------------------------
# Next-action decision — the "brains" of the campaign
# ---------------------------------------------------------------------------
def _decide_next_action(
    campaign: Campaign,
    graph: Any,
    findings: list,
) -> dict[str, Any]:
    """Analyze the attack-path graph + phase state to decide the next action.

    Returns a dict with keys:
    - ``action``: "launch" | "complete" | "wait"
    - ``targets``: list of target strings (when action=launch)
    - ``engine``: which engine to use (when action=launch)
    - ``phase``: which phase we're in (when action=launch)
    - ``next_phase``: optional phase to advance to
    - ``rationale``: human-readable reason for the decision
    - ``reason``: summary string
    """
    current_phase = campaign.current_phase

    # -- REPORTING phase is always terminal.
    if current_phase == CampaignPhase.REPORTING:
        return {"action": "complete", "reason": "campaign reached REPORTING phase"}

    # -- No findings yet → run RECON if we haven't or it failed.
    if not findings:
        if current_phase == CampaignPhase.RECON and campaign.total_runs_launched == 0:
            return _launch_decision(
                campaign, CampaignPhase.RECON,
                targets=_targets_from_engagement(campaign),
                engine=_engine_for_phase(campaign, CampaignPhase.RECON),
                rationale="initial reconnaissance scan",
            )
        # Recon ran but found nothing → complete.
        if campaign.total_runs_launched > 0:
            return _advance_phase_or_complete(campaign, current_phase, "no findings discovered")
        return _launch_decision(
            campaign, CampaignPhase.RECON,
            targets=_targets_from_engagement(campaign),
            engine=_engine_for_phase(campaign, CampaignPhase.RECON),
            rationale="reconnaissance scan",
        )

    # -- We have findings: let the graph guide us.
    max_severity = graph.summary.max_severity
    by_severity = graph.summary.by_severity

    # Check if current phase is satisfied, and if so, advance.
    phase_satisfied, phase_reason = _is_phase_satisfied(campaign, graph, findings)

    if phase_satisfied:
        next_phase = _next_phase(current_phase)
        if next_phase is None:
            return {"action": "complete", "reason": phase_reason or "all phases complete"}

        # Update campaign phase state.
        target = _next_target_for_phase(campaign, graph, next_phase)
        if target is None:
            # Nothing to do in next phase either → complete.
            return {"action": "complete", "reason": f"{phase_reason}. No targets for {next_phase.value}"}

        return _launch_decision(
            campaign, next_phase,
            targets=target["targets"],
            engine=target["engine"],
            rationale=target["rationale"],
        )

    # Current phase isn't satisfied → launch another run in this phase.
    target = _next_target_for_phase(campaign, graph, current_phase)
    if target is None:
        # Nothing left to do in current phase but it's not satisfied — wait.
        return {
            "action": "wait",
            "reason": f"phase {current_phase.value} not satisfied but no actionable targets remain",
        }

    return _launch_decision(
        campaign, current_phase,
        targets=target["targets"],
        engine=target["engine"],
        rationale=target["rationale"],
    )


def _launch_decision(
    campaign: Campaign,
    phase: CampaignPhase,
    *,
    targets: list[str],
    engine: str,
    rationale: str,
) -> dict[str, Any]:
    return {
        "action": "launch",
        "targets": targets,
        "engine": engine,
        "phase": phase,
        "rationale": rationale,
        "reason": f"launching {engine} against {len(targets)} target(s) for {phase.value}: {rationale}",
    }


def _advance_phase_or_complete(
    campaign: Campaign,
    current_phase: CampaignPhase,
    reason: str,
) -> dict[str, Any]:
    next_phase = _next_phase(current_phase)
    if next_phase is None:
        return {"action": "complete", "reason": reason}
    # Advance phase marker in phase_state.
    campaign.phase_state["completed_phases"] = campaign.phase_state.get("completed_phases", [])
    campaign.phase_state["completed_phases"].append(_enum_value(current_phase))
    return {"action": "complete" if next_phase == CampaignPhase.REPORTING else "wait", "reason": reason}


def _next_phase(current: CampaignPhase) -> CampaignPhase | None:
    try:
        idx = _PHASE_SEQUENCE.index(current)
        if idx + 1 < len(_PHASE_SEQUENCE):
            return _PHASE_SEQUENCE[idx + 1]
        return None
    except ValueError:
        return None


def _is_phase_satisfied(
    campaign: Campaign,
    graph: Any,
    findings: list,
) -> tuple[bool, str | None]:
    """Check if the current phase's objectives are met.

    Simple heuristic for prototype:
    - RECON: satisfied if at least one host + one finding discovered.
    - EXPLOIT: satisfied if at least one HIGH/CRITICAL finding.
    - PRIVILEGE_ESCALATION: satisfied if at least one finding with endpoint.
    - LATERAL_MOVEMENT: satisfied if 2+ distinct hosts have findings.
    - PERSISTENCE: satisfied if at least one secret or credential finding.
    - REPORTING: always satisfied.
    """
    phase = campaign.current_phase
    if phase == CampaignPhase.RECON:
        if graph.summary.host_count >= 1 and graph.summary.finding_count >= 1:
            return True, "recon complete: hosts and findings discovered"
        return False, None
    if phase == CampaignPhase.EXPLOIT:
        has_critical = graph.summary.max_severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)
        if has_critical or graph.summary.finding_count >= 3:
            return True, "exploit phase complete: exploitable findings identified"
        return False, None
    if phase == CampaignPhase.PRIVILEGE_ESCALATION:
        host_count = graph.summary.host_count
        if host_count >= 2 and graph.summary.finding_count >= 2:
            return True, "escalation phase complete: multiple hosts compromised"
        return False, None
    if phase == CampaignPhase.LATERAL_MOVEMENT:
        if graph.summary.host_count >= 3 and graph.summary.finding_count >= 5:
            return True, "lateral movement phase complete: broad coverage achieved"
        return False, None
    if phase == CampaignPhase.PERSISTENCE:
        # Look for findings tagged as credential/secret-related (heuristic via title).
        secret_findings = [f for f in findings if _is_secret_finding(f)]
        if secret_findings:
            return True, "persistence phase complete: credentials/secrets discovered"
        if graph.summary.finding_count >= 10:
            return True, "persistence phase complete: comprehensive findings coverage"
        return False, None
    if phase == CampaignPhase.REPORTING:
        return True, "reporting phase"
    return False, None


def _is_secret_finding(finding: Any) -> bool:
    title = (finding.title or "").lower()
    keywords = ["secret", "credential", "password", "token", "key", "certificate", "pem", "env", "aksk"]
    return any(k in title for k in keywords)


def _next_target_for_phase(
    campaign: Campaign,
    graph: Any,
    phase: CampaignPhase,
) -> dict | None:
    """Select the next target for a phase based on the attack-path graph.

    Returns {targets: [str], engine: str, rationale: str} or None.
    """
    if phase == CampaignPhase.RECON:
        # For recon, scan all engagement scope targets (starting point).
        return {
            "targets": _targets_from_engagement(campaign),
            "engine": _engine_for_phase(campaign, CampaignPhase.RECON),
            "rationale": "reconnaissance of engagement scope targets",
        }

    if phase == CampaignPhase.EXPLOIT:
        # For exploit, target hosts with findings.
        hosts = _hosts_from_graph(graph)
        if hosts:
            return {
                "targets": hosts[:3],  # Limit to top 3 hosts
                "engine": _engine_for_phase(campaign, CampaignPhase.EXPLOIT),
                "rationale": f"exploit targeting top {min(3, len(hosts))} host(s) from recon findings",
            }
        return None

    if phase == CampaignPhase.PRIVILEGE_ESCALATION:
        hosts = _hosts_from_graph(graph)
        if len(hosts) >= 2:
            return {
                "targets": hosts[:2],
                "engine": _engine_for_phase(campaign, CampaignPhase.PRIVILEGE_ESCALATION),
                "rationale": "privilege escalation targeting identified hosts",
            }
        return None

    if phase == CampaignPhase.LATERAL_MOVEMENT:
        hosts = _hosts_from_graph(graph)
        return {
            "targets": hosts[:5] if hosts else _targets_from_engagement(campaign),
            "engine": _engine_for_phase(campaign, CampaignPhase.LATERAL_MOVEMENT),
            "rationale": "lateral movement sweep across discovered hosts",
        }

    if phase == CampaignPhase.PERSISTENCE:
        return {
            "targets": _targets_from_engagement(campaign),
            "engine": _engine_for_phase(campaign, CampaignPhase.PERSISTENCE),
            "rationale": "persistence and data exfiltration surface scan",
        }

    return None


def _targets_from_engagement(campaign: Campaign) -> list[str]:
    """Extract target strings from the campaign's engagement scope."""
    # For prototype, we derive from phase_state if set, otherwise empty.
    # In production this reads from the engagement's scope rules.
    return campaign.phase_state.get("scope_targets", [])


def _hosts_from_graph(graph: Any) -> list[str]:
    """Extract host labels from the attack-path graph."""
    hosts = []
    for node in graph.nodes:
        if node.type == "host" and node.label not in ("(unspecified host)",):
            hosts.append(node.label)
    return hosts


def _engine_for_phase(campaign: Campaign, phase: CampaignPhase) -> str:
    """Resolve the engine for a phase, using campaign overrides or defaults."""
    engines = campaign.phase_engines
    if isinstance(engines, dict):
        phase_key = _enum_value(phase)
        configured = engines.get(phase_key) or engines.get(phase.value)
        if configured and isinstance(configured, list) and len(configured) > 0:
            return configured[0]
    defaults = _DEFAULT_PHASE_ENGINES.get(phase, [])
    return defaults[0] if defaults else "strix"


# ---------------------------------------------------------------------------
# Launch a run within the campaign
# ---------------------------------------------------------------------------
async def _launch_campaign_run(
    session: AsyncSession,
    campaign: Campaign,
    actor: "AuthUser",
    decision: dict,
) -> CampaignRun:
    """Create a CampaignRun + the underlying Run (gate-checked)."""
    from app.schemas.run import RunCreate  # Lazy import to avoid cycles

    targets = decision.get("targets", [])
    engine = decision.get("engine", "strix")
    phase = decision.get("phase", campaign.current_phase)
    rationale = decision.get("rationale", "")

    if not targets:
        raise ValidationAppError("no targets to launch", detail={"campaign_id": str(campaign.id)})

    campaign_run = CampaignRun(
        id=uuid.uuid4(),
        campaign_id=campaign.id,
        org_id=campaign.org_id,
        phase=phase,
        status=CampaignRunStatus.PENDING,
        engine=engine,
        targets=targets,
        rationale=rationale,
    )
    session.add(campaign_run)
    await session.flush()

    # Update campaign accumulators.
    campaign.total_runs_launched += 1
    if campaign.status == CampaignStatus.ACTIVE:
        campaign.status = CampaignStatus.IN_PROGRESS
        campaign.started_at = campaign.started_at or _utcnow()
        campaign.first_run_at = campaign.first_run_at or _utcnow()
    if campaign.current_phase != phase:
        campaign.current_phase = phase

    # Create the concrete Run through the gate-enforced path.
    run_data = RunCreate(
        mode="standard",
        model_profile="hybrid-local-sweep-verify",
        targets=targets,
        engine=engine,
    )
    engagement = await EngagementRepository(session).get(campaign.engagement_id)
    from app.services.runs import start_run

    run = await start_run(
        session,
        engagement=engagement,
        actor=actor,
        data=run_data,
    )

    campaign_run.run_id = run.id
    campaign_run.status = CampaignRunStatus.IN_PROGRESS
    campaign_run.started_at = _utcnow()

    await record_event(
        session,
        action=AuditAction.CAMPAIGN_RUN_CREATED,
        actor=actor,
        org_id=campaign.org_id,
        engagement_id=campaign.engagement_id,
        run_id=run.id,
        decision="launched",
        reason=f"campaign run #{campaign.total_runs_launched} {engine} phase={_enum_value(phase)}",
        detail={
            "campaign_id": str(campaign.id),
            "campaign_run_id": str(campaign_run.id),
            "engine": engine,
            "targets": targets,
            "phase": _enum_value(phase),
        },
    )
    return campaign_run


# ---------------------------------------------------------------------------
# Stop / Cancel / Restart / Approve
# ---------------------------------------------------------------------------
async def _stop_campaign(
    session: AsyncSession,
    campaign: Campaign,
    *,
    actor: "AuthUser",
    note: str | None = None,
) -> dict[str, Any]:
    if campaign.status in _TERMINAL_CAMPAIGN_STATUSES:
        return {"campaign": campaign, "created_run": None, "action_taken": "noop",
                "message": "campaign already terminal", "budget_remaining_pct": _budget_remaining(campaign)}

    campaign.status = CampaignStatus.STOPPED
    campaign.ended_at = _utcnow()
    await _audit_decision(session, campaign, actor, "stopped", note or "campaign stopped by operator")
    await session.commit()
    return {"campaign": campaign, "created_run": None, "action_taken": "stopped",
            "message": "campaign stopped", "budget_remaining_pct": _budget_remaining(campaign)}


async def _cancel_campaign(
    session: AsyncSession,
    campaign: Campaign,
    *,
    actor: "AuthUser",
    note: str | None = None,
) -> dict[str, Any]:
    if campaign.status in _TERMINAL_CAMPAIGN_STATUSES:
        return {"campaign": campaign, "created_run": None, "action_taken": "noop",
                "message": "campaign already terminal", "budget_remaining_pct": _budget_remaining(campaign)}

    campaign.status = CampaignStatus.CANCELLED
    campaign.ended_at = _utcnow()
    await _audit_decision(session, campaign, actor, "cancelled", note or "campaign cancelled")
    await session.commit()
    return {"campaign": campaign, "created_run": None, "action_taken": "cancelled",
            "message": "campaign cancelled", "budget_remaining_pct": _budget_remaining(campaign)}


async def _restart_campaign(
    session: AsyncSession,
    campaign: Campaign,
    *,
    actor: "AuthUser",
    note: str | None = None,
) -> dict[str, Any]:
    if campaign.status not in (CampaignStatus.STOPPED, CampaignStatus.ACTIVE, CampaignStatus.DRAFT):
        return {"campaign": campaign, "created_run": None, "action_taken": "blocked",
                "message": f"cannot restart from {campaign.status.value}",
                "budget_remaining_pct": _budget_remaining(campaign)}

    campaign.status = CampaignStatus.ACTIVE
    campaign.error = None
    campaign.resumed_by = actor.username if hasattr(actor, "username") else str(actor)
    campaign.resumed_at = _utcnow()
    await _audit_decision(session, campaign, actor, "restarted", note or "campaign restarted")
    await session.commit()
    return {"campaign": campaign, "created_run": None, "action_taken": "restarted",
            "message": "campaign restarted", "budget_remaining_pct": _budget_remaining(campaign)}


async def _approve_campaign(
    session: AsyncSession,
    campaign: Campaign,
    *,
    actor: "AuthUser",
    resume_phase: CampaignPhase | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    if campaign.status != CampaignStatus.WAITING_APPROVAL:
        return {"campaign": campaign, "created_run": None, "action_taken": "blocked",
                "message": f"campaign is {campaign.status.value}, not WAITING_APPROVAL",
                "budget_remaining_pct": _budget_remaining(campaign)}

    campaign.status = CampaignStatus.IN_PROGRESS
    campaign.resumed_by = actor.username if hasattr(actor, "username") else str(actor)
    campaign.resumed_at = _utcnow()
    if resume_phase is not None:
        campaign.current_phase = resume_phase
    await _audit_decision(session, campaign, actor, "approved", note or "campaign approved by human")
    await session.commit()
    return {"campaign": campaign, "created_run": None, "action_taken": "approved",
            "message": "campaign resumed", "budget_remaining_pct": _budget_remaining(campaign)}


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------
async def _audit_decision(
    session: AsyncSession,
    campaign: Campaign,
    actor: "AuthUser",
    decision: str,
    reason: str,
) -> None:
    try:
        await record_event(
            session,
            action=AuditAction.CAMPAIGN_ADVANCED,
            actor=actor,
            org_id=campaign.org_id,
            engagement_id=campaign.engagement_id,
            run_id=None,
            decision=decision,
            reason=reason,
            detail={
                "campaign_id": str(campaign.id),
                "status": _enum_value(campaign.status),
                "phase": _enum_value(campaign.current_phase),
                "total_runs": campaign.total_runs_launched,
                "total_cost": str(campaign.total_cost_usd),
            },
        )
    except Exception:  # noqa: BLE001
        logger.exception("failed to audit campaign decision for %s", campaign.id)


__all__ = [
    "create_campaign",
    "activate_campaign",
    "advance_campaign",
]
