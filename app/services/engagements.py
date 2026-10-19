"""Engagement lifecycle service (spec §4/§6).

Owns creation and the DRAFT -> ACTIVE / emergency-stop transitions of the
scope-of-engagement record the authorization gate enforces. Services own their
transactions (they commit) and emit the append-only audit rows; the routes in
``app.api.engagements`` stay thin.

Key rule — :func:`activate_engagement` fails **closed**: an engagement may only go
ACTIVE when it has at least one in-scope target and *every* in-scope rule is
covered by a registered :class:`~app.models.target.AuthorizedTarget` with a
currently-valid attestation (reusing the exact scope/attestation machinery the
gate uses at run time). This makes "an ACTIVE engagement" a meaningful safety
claim rather than a label.

Dependency direction (no cycles): services -> {authz.scope, authz.attestation,
audit.writer, core.errors, repositories, models}. Nothing there imports services.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.writer import record_event
from app.authz.attestation import attestation_is_valid
from app.authz.scope import normalize_target
from app.core.errors import ConflictError, ValidationAppError
from app.models.audit import AuditAction
from app.models.engagement import Engagement, EngagementStatus
from app.repositories.targets import TargetRepository

if TYPE_CHECKING:  # typing only — no runtime coupling / cycle
    from app.auth.sso import AuthUser
    from app.models.organization import Organization
    from app.schemas.engagement import EngagementCreate, EngagementScope

logger = logging.getLogger("secops.services.engagements")

# Source states from which an engagement may be (re-)activated.
_ACTIVATABLE_FROM: frozenset[EngagementStatus] = frozenset(
    {EngagementStatus.DRAFT, EngagementStatus.PAUSED}
)


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


def _actor_ref(actor: "AuthUser | str | None") -> str:
    """Stable string id for the ``created_by`` column — id, then email, then repr.

    Aligns with the audit writer's ``actor_id`` so ``engagement.created_by`` can be
    correlated with the ``ENGAGEMENT_CREATED`` audit row's actor.
    """
    if actor is None:
        return "unknown"
    if isinstance(actor, str):
        return actor
    ref = getattr(actor, "id", None) or getattr(actor, "email", None)
    return str(ref) if ref else str(actor)


def _scope_column(scope: "EngagementScope") -> dict[str, Any]:
    """The ``{in_scope, exclusions}`` half persisted in the ``scope`` column.

    Rules-of-engagement live in the sibling ``rules_of_engagement`` column (the
    gate merges the two back together via ``EngagementScope`` at evaluation time),
    so they are deliberately excluded here. ``mode="json"`` yields JSON-native
    values (enum ``kind`` -> its string, datetimes -> ISO) for JSONB storage,
    matching what ``scripts/seed_pilot`` writes by hand.
    """
    return {
        "in_scope": [rule.model_dump(mode="json") for rule in scope.in_scope],
        "exclusions": [rule.model_dump(mode="json") for rule in scope.exclusions],
    }


async def create_engagement(
    session: AsyncSession,
    *,
    org: "Organization",
    actor: "AuthUser",
    data: "EngagementCreate",
) -> Engagement:
    """Create a DRAFT engagement with its scope-of-engagement (audited).

    Splits the request's ``EngagementScope`` into the persisted ``scope``
    (``{in_scope, exclusions}``) and sibling ``rules_of_engagement`` columns,
    stamps ``created_by`` from the actor, appends an ``ENGAGEMENT_CREATED`` audit
    row, commits, and returns the engagement. Activation (and its attestation
    checks) is a separate step — a fresh engagement is never ACTIVE.
    """
    engagement = Engagement(
        org_id=org.id,
        name=data.name,
        status=EngagementStatus.DRAFT,
        scope=_scope_column(data.scope),
        rules_of_engagement=data.scope.rules_of_engagement.model_dump(mode="json"),
        model_profile=data.model_profile,
        created_by=_actor_ref(actor),
        starts_at=data.starts_at,
        expires_at=data.expires_at,
        emergency_stopped=False,
    )
    session.add(engagement)
    await session.flush()

    await record_event(
        session,
        action=AuditAction.ENGAGEMENT_CREATED,
        actor=actor,
        org_id=org.id,
        engagement_id=engagement.id,
        reason=f"engagement {data.name!r} created (DRAFT)",
        detail={
            "name": data.name,
            "model_profile": data.model_profile,
            "in_scope": len(data.scope.in_scope),
            "exclusions": len(data.scope.exclusions),
            "expires_at": data.expires_at.isoformat() if data.expires_at else None,
        },
    )
    await session.commit()
    return engagement


async def activate_engagement(
    session: AsyncSession,
    *,
    engagement: Engagement,
    actor: "AuthUser",
) -> Engagement:
    """Transition an engagement to ACTIVE — fail-closed on scope/attestation.

    Refuses (409 ``ConflictError``) an emergency-stopped or non-activatable
    engagement; is idempotent when already ACTIVE. Refuses (422
    ``ValidationAppError``) when the engagement has already expired, has no
    in-scope targets, or any in-scope rule is not covered by a valid attested
    :class:`~app.models.target.AuthorizedTarget` (the same coverage +
    ``attestation_is_valid`` machinery the gate applies at run time). Only then is
    the status flipped and an ``ENGAGEMENT_ACTIVATED`` audit row appended.
    """
    if engagement.emergency_stopped:
        raise ConflictError(
            "cannot activate an emergency-stopped engagement",
            detail={"engagement_id": str(engagement.id)},
        )
    if engagement.status == EngagementStatus.ACTIVE:
        return engagement  # idempotent
    if engagement.status not in _ACTIVATABLE_FROM:
        raise ConflictError(
            f"cannot activate an engagement in status {engagement.status.value}",
            detail={"status": engagement.status.value},
        )

    now = _utcnow()
    expires_at = _aware(engagement.expires_at)
    if expires_at is not None and expires_at <= now:
        raise ValidationAppError(
            "cannot activate an engagement that has already expired",
            code="engagement_expired",
            detail={"expires_at": expires_at.isoformat()},
        )

    in_scope_rules = list((engagement.scope or {}).get("in_scope") or [])
    if not in_scope_rules:
        raise ValidationAppError(
            "cannot activate: the engagement has no in-scope targets",
            code="engagement_scope_empty",
        )
    uncovered = await _uncovered_in_scope(session, engagement, in_scope_rules, now=now)
    if uncovered:
        raise ValidationAppError(
            "cannot activate: some in-scope targets are not covered by a valid "
            "attested target",
            code="engagement_scope_unattested",
            detail={"uncovered": uncovered},
        )

    engagement.status = EngagementStatus.ACTIVE
    if engagement.starts_at is None:
        engagement.starts_at = now
    await session.flush()

    await record_event(
        session,
        action=AuditAction.ENGAGEMENT_ACTIVATED,
        actor=actor,
        org_id=engagement.org_id,
        engagement_id=engagement.id,
        decision="allow",
        reason="engagement activated",
        detail={"in_scope": len(in_scope_rules)},
    )
    await session.commit()
    return engagement


async def emergency_stop(
    session: AsyncSession,
    *,
    engagement: Engagement,
    actor: "AuthUser",
) -> Engagement:
    """Emergency-stop an engagement: set the kill flag + status STOPPED (audited).

    The kill flag wins over everything (the gate refuses any target of an
    emergency-stopped engagement). Idempotent: a repeated stop on an
    already-stopped engagement returns it unchanged without a duplicate audit row.
    """
    if engagement.emergency_stopped:
        return engagement  # already killed — idempotent

    previous_status = engagement.status
    engagement.emergency_stopped = True
    engagement.status = EngagementStatus.STOPPED
    await session.flush()

    await record_event(
        session,
        action=AuditAction.EMERGENCY_STOP,
        actor=actor,
        org_id=engagement.org_id,
        engagement_id=engagement.id,
        decision="deny",
        reason="engagement emergency-stopped",
        detail={"previous_status": getattr(previous_status, "value", previous_status)},
    )
    await session.commit()
    return engagement


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------
async def _uncovered_in_scope(
    session: AsyncSession,
    engagement: Engagement,
    in_scope_rules: list[Any],
    *,
    now: datetime,
) -> list[dict[str, Any]]:
    """Return the in-scope rules NOT covered by a valid attested target.

    Each rule's ``value`` is treated as a concrete target and run through the same
    ``normalize_target`` + ``TargetRepository.find_covering`` + ``attestation_is_valid``
    path the gate uses, so activation guarantees each in-scope rule would itself
    clear the gate. An empty list means every rule is covered.
    """
    repo = TargetRepository(session)
    uncovered: list[dict[str, Any]] = []
    for rule in in_scope_rules:
        value = rule.get("value") if isinstance(rule, dict) else getattr(rule, "value", None)
        if not value:
            uncovered.append({"value": None, "reason": "empty_value"})
            continue
        try:
            normalized = normalize_target(str(value))
        except Exception:  # noqa: BLE001 - unparseable rule can never be authorized
            uncovered.append({"value": value, "reason": "unnormalizable"})
            continue
        covering = await repo.find_covering(engagement.org_id, normalized)
        if not any(attestation_is_valid(target, now=now) for target in covering):
            uncovered.append({"value": value, "reason": "no_valid_attested_target"})
    return uncovered


__all__ = ["create_engagement", "activate_engagement", "emergency_stop"]
