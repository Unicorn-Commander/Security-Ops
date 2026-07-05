"""app.audit.writer — the canonical, append-only audit writer (spec §4/§5).

``record_event`` is the ONE way anything in Security-Ops appends to the immutable
audit log. Every audit surface funnels through it so the tamper-evident hash chain
stays single-sourced:

* the authorization gate — via :func:`app.authz.audit.record_scope_decision`
  (``SCOPE_CHECK_ALLOWED`` / ``SCOPE_CHECK_DENIED``);
* the entitlement gate — :func:`app.auth.entitlement._record_entitlement_denied`
  (``ENTITLEMENT_DENIED``);
* the Strix runner — per-finding ``FINDING_RECORDED`` and run-lifecycle events;
* the Brigade hand-off — ``FINDING_HANDOFF``.

For each call it resolves the actor to ``(actor_id, actor_email)``, reads the
current chain head, builds an :class:`~app.models.audit.AuditEvent`, links it onto
the chain (``prev_hash -> event_hash`` via :mod:`app.audit.chain`), and inserts it.

Transaction contract (suite convention): this **flushes, never commits** — the
caller (route / service / background worker) owns the transaction boundary. The
flush surfaces the ``event_hash`` unique constraint immediately and makes the new
row visible so a subsequent ``record_event`` in the same session chains onto it.
The one caller that commits itself (``_record_entitlement_denied``, which must
persist across the impending 403) does so explicitly after this returns.

Concurrency: chain-head selection assumes a single writer at a time (the Phase-1
single-worker container). Serialized multi-writer appends (row-lock / sequence) are
Phase-3 hardening, alongside the DB trigger that denies UPDATE/DELETE.

Dependency direction (no cycles): writer -> {audit.chain, models.audit, sqlalchemy}.
``AuthUser`` is referenced for typing only; the actor is duck-typed at runtime, so
there is no import-time coupling to ``app.auth``.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.chain import assign_event_hash
from app.models.audit import AuditAction, AuditEvent

if TYPE_CHECKING:  # typing only — avoids any runtime import cycle with app.auth
    from app.auth.sso import AuthUser

log = logging.getLogger("secops.audit.writer")

__all__ = ["record_event"]


def _actor_fields(actor: "AuthUser | str | None") -> tuple[str, str | None]:
    """Resolve an actor to ``(actor_id, actor_email)``.

    Accepts either a system actor string (e.g. ``"system:strix-runner"``) or an
    :class:`~app.auth.sso.AuthUser`-shaped principal (duck-typed: ``.id`` / ``.email``).
    ``actor_id`` is NOT NULL in the schema, so a non-empty string is always returned.
    """
    if actor is None:
        return ("unknown", None)
    if isinstance(actor, str):
        return (actor, None)
    actor_id = getattr(actor, "id", None)
    actor_email = getattr(actor, "email", None)
    resolved = str(actor_id) if actor_id is not None else str(actor)
    return (resolved, actor_email if isinstance(actor_email, str) else None)


def _coerce_action(action: "AuditAction | str") -> AuditAction:
    """Return an :class:`AuditAction` (all callers pass the enum; strings tolerated)."""
    if isinstance(action, AuditAction):
        return action
    return AuditAction(action)  # raises ValueError on an unknown value


async def _chain_head_hash(session: AsyncSession) -> str | None:
    """``event_hash`` of the current chain head, or ``None`` when the log is empty.

    The head is the most-recently appended row. ``created_at`` is written explicitly
    (see :func:`record_event`) so it is strictly increasing per append; ``event_hash``
    is a deterministic tie-breaker purely to make head selection repeatable.
    """
    result = await session.execute(
        select(AuditEvent.event_hash)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.event_hash.desc())
        .limit(1)
    )
    return result.scalars().first()


async def record_event(
    session: AsyncSession,
    *,
    action: "AuditAction | str",
    actor: "AuthUser | str",
    org_id: uuid.UUID | None = None,
    engagement_id: uuid.UUID | None = None,
    run_id: uuid.UUID | None = None,
    target: str | None = None,
    target_id: uuid.UUID | None = None,
    decision: str | None = None,
    reason: str | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    """Append exactly one immutable :class:`AuditEvent` and return it.

    Args:
        session: the active :class:`AsyncSession`; this function flushes but does not
            commit (the caller owns the transaction).
        action: the :class:`AuditAction` (or its value string) being recorded.
        actor: the principal responsible — an :class:`~app.auth.sso.AuthUser` or a
            system-actor string; resolved to ``actor_id`` / ``actor_email``.
        org_id, engagement_id, run_id, target_id: optional scope references (plain
            UUIDs, no FK — the audit row outlives the entities it references).
        target: optional human-readable target (domain / URL / endpoint).
        decision: optional coarse verdict (``"allow"`` / ``"deny"`` / ``"handoff"`` / …).
        reason: optional human-readable cause.
        detail: optional JSON-serializable structured context (machine codes,
            violations, severities, cost, etc.).

    The event is linked onto the tamper-evident chain (its ``prev_hash`` is the
    current head's ``event_hash`` — or ``None`` for the genesis event — and its
    ``event_hash`` is computed over its content plus that link). ``id`` and
    ``created_at`` are assigned here (not left to server defaults) so the hashed
    payload is fully determined before insert.
    """
    actor_id, actor_email = _actor_fields(actor)
    prev_hash = await _chain_head_hash(session)

    event = AuditEvent(
        id=uuid.uuid4(),
        action=_coerce_action(action),
        actor_id=actor_id,
        actor_email=actor_email,
        org_id=org_id,
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
        target_id=target_id,
        decision=decision,
        reason=reason,
        detail=detail,
        created_at=datetime.now(timezone.utc),
    )
    assign_event_hash(event, prev_hash)

    session.add(event)
    # Flush (not commit): enforce the event_hash uniqueness now and make this row
    # visible so the next record_event in this session chains onto it.
    await session.flush()

    log.debug(
        "audit.record action=%s actor=%s decision=%s hash=%s prev=%s",
        getattr(event.action, "value", event.action),
        actor_id,
        decision,
        event.event_hash[:12],
        (prev_hash[:12] if prev_hash else "GENESIS"),
    )
    return event
