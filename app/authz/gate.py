"""app.authz.gate — THE authorization chokepoint (spec §4). This is the IP.

No scan/run may touch a target unless :func:`enforce_scope` returns cleanly. The
gate is **server-side and authoritative**; the offensive engine is NEVER trusted
to self-limit (belt-and-suspenders ``--instruction-file`` scoping is Phase 2, but
it is advisory — this function is the real boundary).

Two entry points, one shared evaluator:

* :func:`enforce_scope` — the gate proper, invoked by
  ``app.services.runs.start_run`` for EVERY concrete target of a run. It loads the
  engagement, gates on engagement-level state (existence / ``ACTIVE`` / not
  expired / inside the RoE time window / not emergency-stopped, and the global
  ``settings.emergency_stop_all`` kill-switch), then evaluates scope + attestation,
  appends **exactly one** immutable audit row, and raises the matching
  :class:`~app.authz.errors.AuthorizationDenied` subclass (HTTP 403) on any denial.
  Returns ``None`` on success. Side effect = exactly one audit row per call.

* :func:`check_scope` — the PURE, side-effect-free scope + attestation evaluation
  behind ``POST /engagements/{id}/scope/check``. No audit write, no raise; returns
  a :class:`~app.authz.dto.ScopeDecision` the UI can preview before a run.

Import direction (no cycles): gate -> {authz.scope, authz.attestation, authz.dto,
authz.errors, authz.audit, repositories, schemas.engagement, models, core.config}.
The gate never imports services or api.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from app.authz.attestation import attestation_is_valid
from app.authz.audit import record_scope_decision
from app.authz.dto import ScopeDecision
from app.authz.errors import (
    AttestationExpired,
    AuthorizationDenied,
    EmergencyStopEngaged,
    EngagementExpired,
    EngagementInactive,
    OutsideTimeWindow,
    ScopeViolation,
    TargetExcluded,
    TargetNotAttested,
)
from app.authz.scope import normalize_target, target_in_scope
from app.core.config import settings
from app.models.engagement import Engagement, EngagementStatus
from app.models.target import AttestationStatus
from app.repositories.engagements import EngagementRepository
from app.repositories.targets import TargetRepository
from app.schemas.engagement import EngagementScope, RulesOfEngagement

if TYPE_CHECKING:  # pragma: no cover - typing only; never imported at runtime
    # AuthUser lives in app.auth.sso in this build; the gate only forwards it to
    # the audit writer, never introspects it, so this is annotation-only.
    from app.auth.sso import AuthUser

# ---------------------------------------------------------------------------
# Decision codes. Denial codes map 1:1 to the concrete AuthorizationDenied
# subclass raised by enforce_scope (each surfaces as HTTP 403 with error.code).
# ---------------------------------------------------------------------------
ALLOWED_CODE = "allowed"

_ERROR_BY_CODE: dict[str, type[AuthorizationDenied]] = {
    "engagement_inactive": EngagementInactive,
    "engagement_expired": EngagementExpired,
    "outside_time_window": OutsideTimeWindow,
    "emergency_stop_engaged": EmergencyStopEngaged,
    "scope_violation": ScopeViolation,
    "target_excluded": TargetExcluded,
    "target_not_attested": TargetNotAttested,
    "attestation_expired": AttestationExpired,
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    """Normalize a persisted or internal timestamp to aware UTC (naive = UTC).

    Client input is converted at the API schema boundary (app.core.time), where a
    naive value means business time. Values read back from storage or built
    internally are UTC.
    """
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _decision(
    *,
    allowed: bool,
    code: str,
    reason: str,
    engagement_id: uuid.UUID,
    target: str,
    matched_target_id: uuid.UUID | None = None,
    violations: list[str] | None = None,
) -> ScopeDecision:
    return ScopeDecision(
        allowed=allowed,
        code=code,
        reason=reason,
        engagement_id=engagement_id,
        target=target,
        matched_target_id=matched_target_id,
        violations=violations or [],
    )


def _error_for(decision: ScopeDecision) -> AuthorizationDenied:
    """Map a denial ScopeDecision to its concrete 403 error (carrying .reason)."""
    cls = _ERROR_BY_CODE.get(decision.code, AuthorizationDenied)
    return cls(decision.reason)


# ---------------------------------------------------------------------------
# Step 1 — engagement-level gating (enforce_scope only)
# ---------------------------------------------------------------------------
def _time_window_denial(
    engagement: Engagement,
    engagement_id: uuid.UUID,
    target: str,
    *,
    now: datetime,
) -> ScopeDecision | None:
    """Deny if ``now`` is outside the rules-of-engagement time window. An absent or
    unparseable window imposes no time restriction (it is an optional narrowing)."""
    try:
        roe = RulesOfEngagement.model_validate(engagement.rules_of_engagement or {})
        start = _aware(roe.time_window_start)
        end = _aware(roe.time_window_end)
    except Exception:  # pragma: no cover - malformed RoE => no window narrowing
        return None
    if start is not None and now < start:
        return _decision(
            allowed=False,
            code="outside_time_window",
            reason="current time is before the engagement time window",
            engagement_id=engagement_id,
            target=target,
            violations=["before_window"],
        )
    if end is not None and now > end:
        return _decision(
            allowed=False,
            code="outside_time_window",
            reason="current time is after the engagement time window",
            engagement_id=engagement_id,
            target=target,
            violations=["after_window"],
        )
    return None


def _engagement_denial(
    engagement: Engagement | None,
    engagement_id: uuid.UUID,
    target: str,
    *,
    now: datetime,
) -> ScopeDecision | None:
    """Engagement-level gate (spec §4 step 1). Returns a DENY decision, or ``None``
    when the engagement is live and scope/attestation may be evaluated (step 2)."""
    # Global kill-switch wins over everything else.
    if settings.emergency_stop_all:
        return _decision(
            allowed=False,
            code="emergency_stop_engaged",
            reason="global emergency stop is engaged",
            engagement_id=engagement_id,
            target=target,
            violations=["emergency_stop_all"],
        )
    if engagement is None:
        return _decision(
            allowed=False,
            code="engagement_inactive",
            reason="engagement not found",
            engagement_id=engagement_id,
            target=target,
            violations=["engagement_not_found"],
        )
    if engagement.emergency_stopped:
        return _decision(
            allowed=False,
            code="emergency_stop_engaged",
            reason="engagement is emergency-stopped",
            engagement_id=engagement_id,
            target=target,
            violations=["engagement_emergency_stopped"],
        )
    if engagement.status != EngagementStatus.ACTIVE:
        status = getattr(engagement.status, "value", engagement.status)
        return _decision(
            allowed=False,
            code="engagement_inactive",
            reason=f"engagement is not ACTIVE (status={status})",
            engagement_id=engagement_id,
            target=target,
            violations=[f"status:{status}"],
        )
    expires_at = _aware(engagement.expires_at)
    if expires_at is not None and expires_at <= now:
        return _decision(
            allowed=False,
            code="engagement_expired",
            reason="engagement has expired",
            engagement_id=engagement_id,
            target=target,
            violations=["engagement_expired"],
        )
    return _time_window_denial(engagement, engagement_id, target, now=now)


# ---------------------------------------------------------------------------
# Step 2 — scope + attestation (shared by check_scope and enforce_scope)
# ---------------------------------------------------------------------------
def _load_scope(engagement: Engagement) -> EngagementScope:
    """Rebuild the typed EngagementScope the matcher expects. The ``scope`` column
    persists only ``{in_scope, exclusions}`` (RoE is a sibling column), so merge the
    engagement's rules_of_engagement back in to satisfy the schema."""
    scope_data = dict(engagement.scope or {})
    scope_data.setdefault("rules_of_engagement", engagement.rules_of_engagement or {})
    return EngagementScope.model_validate(scope_data)


async def _evaluate_scope(
    session: AsyncSession,
    engagement: Engagement | None,
    engagement_id: uuid.UUID,
    target: str,
    *,
    now: datetime,
) -> ScopeDecision:
    """PURE scope + attestation evaluation -> ScopeDecision. No audit, no raise.

    A target is authorized only when it is (a) within the engagement's in-scope
    rules, (b) not matched by any exclusion (exclusion wins), and (c) covered by a
    registered :class:`AuthorizedTarget` whose attestation is currently valid.
    """
    if engagement is None:
        return _decision(
            allowed=False,
            code="engagement_inactive",
            reason="engagement not found",
            engagement_id=engagement_id,
            target=target,
            violations=["engagement_not_found"],
        )

    scope = _load_scope(engagement)
    match = target_in_scope(scope, target)

    # Exclusion wins over in-scope membership.
    if match.excluded:
        return _decision(
            allowed=False,
            code="target_excluded",
            reason="target matches an explicit scope exclusion",
            engagement_id=engagement_id,
            target=target,
            violations=["excluded"],
        )
    if not match.in_scope:
        return _decision(
            allowed=False,
            code="scope_violation",
            reason="target is not within the engagement in-scope rules",
            engagement_id=engagement_id,
            target=target,
            violations=["not_in_scope"],
        )

    # In scope + not excluded -> require a valid attested covering target.
    try:
        nt = normalize_target(target)
    except Exception:
        return _decision(
            allowed=False,
            code="target_not_attested",
            reason="target could not be normalized for attestation lookup",
            engagement_id=engagement_id,
            target=target,
            violations=["unnormalizable_target"],
        )

    covering = await TargetRepository(session).find_covering(engagement.org_id, nt)
    valid = [t for t in covering if attestation_is_valid(t, now=now)]
    if valid:
        return _decision(
            allowed=True,
            code=ALLOWED_CODE,
            reason="target is in scope and covered by a valid attestation",
            engagement_id=engagement_id,
            target=target,
            matched_target_id=valid[0].id,
        )

    # Covered by a registered target whose attestation lapsed/was revoked?
    expired = [
        t
        for t in covering
        if getattr(t, "attestation_status", None) == AttestationStatus.ATTESTED
    ]
    if expired:
        return _decision(
            allowed=False,
            code="attestation_expired",
            reason="covering target's attestation is expired or revoked",
            engagement_id=engagement_id,
            target=target,
            matched_target_id=expired[0].id,
            violations=["attestation_expired"],
        )
    return _decision(
        allowed=False,
        code="target_not_attested",
        reason="no valid attested target covers this target",
        engagement_id=engagement_id,
        target=target,
        violations=["target_not_attested"],
    )


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------
async def check_scope(
    session: AsyncSession,
    engagement_id: uuid.UUID,
    target: str,
) -> ScopeDecision:
    """PURE evaluation: NO audit write, NO raise.

    Loads the engagement and evaluates scope + attestation, returning a
    :class:`ScopeDecision`. Used by :func:`enforce_scope` and by the dry-run
    endpoint ``POST /engagements/{id}/scope/check``. Engagement-level lifecycle
    state (ACTIVE / expiry / window / emergency stop) is intentionally NOT applied
    here — that is enforced by :func:`enforce_scope` — so the UI can preview a
    target's scope/attestation standing independent of run-time gating.
    """
    now = _utcnow()
    engagement = await EngagementRepository(session).get(engagement_id)
    return await _evaluate_scope(session, engagement, engagement_id, target, now=now)


async def enforce_scope(
    session: AsyncSession,
    engagement_id: uuid.UUID,
    target: str,
    *,
    actor: "AuthUser",
    run_id: uuid.UUID | None = None,
) -> None:
    """THE GATE. Authorize (or refuse) one concrete ``target`` under ``engagement_id``.

    Steps (spec §4):

    1. Load the engagement and apply engagement-level gating: it must exist, be
       ``ACTIVE``, be unexpired, be inside its RoE time window, not be
       emergency-stopped, and the global ``settings.emergency_stop_all`` kill-switch
       must be off.
    2. Evaluate scope + attestation (shared with :func:`check_scope`): the target
       must be in-scope, not excluded, and covered by a valid attested
       :class:`AuthorizedTarget`.
    3. ALWAYS append exactly one audit row (``SCOPE_CHECK_ALLOWED`` /
       ``SCOPE_CHECK_DENIED``) via :func:`app.authz.audit.record_scope_decision`,
       which delegates to the canonical hash-chained writer.
    4. On any failure raise the matching :class:`AuthorizationDenied` subclass
       (HTTP 403). Returns ``None`` on success.

    The caller (``services.runs.start_run``) owns the transaction/commit; the gate
    performs no commit. Its only side effect is the single audit append.
    """
    now = _utcnow()
    engagement = await EngagementRepository(session).get(engagement_id)

    # Step 1: engagement-level gate; Step 2: scope + attestation.
    decision = _engagement_denial(engagement, engagement_id, target, now=now)
    if decision is None:
        decision = await _evaluate_scope(
            session, engagement, engagement_id, target, now=now
        )

    # Step 3: exactly one immutable audit row per call (allow or deny).
    org_id = engagement.org_id if engagement is not None else None
    await record_scope_decision(
        session,
        decision=decision,
        actor=actor,
        run_id=run_id,
        org_id=org_id,
    )

    # Step 4: refuse with the specific 403 on denial.
    if not decision.allowed:
        raise _error_for(decision)
    return None
