"""app.authz.audit — the authorization gate's append-only audit facade.

The canonical, hash-chained, append-only writer is suite-wide and lives in
``app.audit.writer`` (with the hash logic in ``app.audit.chain``). This module is
the authz-scoped convenience layer the gate uses to turn a single
:class:`~app.authz.dto.ScopeDecision` into EXACTLY ONE immutable audit row
(``SCOPE_CHECK_ALLOWED`` / ``SCOPE_CHECK_DENIED``), delegating the actual insert +
hash chaining to :func:`app.audit.writer.record_event` so the tamper-evident
chain stays single-sourced across every audit surface (gate, entitlement, runner).

Append-only by construction: there is no update/delete path here — the only
mutation is a single insert via the canonical writer. ``record_event`` is
re-exported so callers can reach the raw writer through the authz package.

Dependency direction (no cycles): authz.audit -> {audit.writer, authz.dto,
models.audit}. It never imports authz.gate / scope / attestation / services / api.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.writer import record_event
from app.authz.dto import ScopeDecision
from app.models.audit import AuditAction, AuditEvent

if TYPE_CHECKING:  # pragma: no cover - typing only; never imported at runtime
    # AuthUser is defined in app.auth.sso in this build; used for annotations only
    # (actor is passed straight through to the canonical writer, never introspected).
    from app.auth.sso import AuthUser

__all__ = ["record_scope_decision", "record_event"]


async def record_scope_decision(
    session: AsyncSession,
    *,
    decision: ScopeDecision,
    actor: "AuthUser | str",
    run_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    target_id: uuid.UUID | None = None,
) -> AuditEvent:
    """Append EXACTLY ONE gate-decision audit row and return it.

    Maps a :class:`ScopeDecision` onto the append-only log:

    * ``decision.allowed`` -> :attr:`AuditAction.SCOPE_CHECK_ALLOWED` else
      :attr:`AuditAction.SCOPE_CHECK_DENIED`;
    * ``decision`` column carries the coarse ``"allow"`` / ``"deny"`` verdict;
    * ``reason`` is the human-readable cause; the machine ``code`` and the list of
      ``violations`` are preserved in ``detail`` for SOC2 export / forensics;
    * ``target_id`` records the covering :class:`AuthorizedTarget` that authorized
      the decision (when one matched), falling back to an explicit ``target_id``.

    Delegates to :func:`app.audit.writer.record_event`, which computes
    ``prev_hash``/``event_hash`` and inserts the row — so the hash chain remains
    continuous with entitlement/lifecycle events written elsewhere. The gate is
    expected to call this exactly once per :func:`enforce_scope` invocation.
    """
    action = (
        AuditAction.SCOPE_CHECK_ALLOWED
        if decision.allowed
        else AuditAction.SCOPE_CHECK_DENIED
    )
    return await record_event(
        session,
        action=action,
        actor=actor,
        org_id=org_id,
        engagement_id=decision.engagement_id,
        run_id=run_id,
        target=decision.target,
        target_id=decision.matched_target_id or target_id,
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        detail={"code": decision.code, "violations": list(decision.violations)},
    )
