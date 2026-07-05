"""app.authz.attestation — AuthorizedTarget attestation: the "is this proven?" half of the gate (spec §4).

Two entry points:

* :func:`attestation_is_valid` — the PURE predicate the gate calls for every
  covering target in its hot path: a target is scannable only when its status is
  ``ATTESTED`` **and** it is neither revoked nor expired at the evaluation instant
  (mirrors ``app.models.target.AuthorizedTarget``'s contract). No I/O, no raise.

* :func:`attest_target` — the WRITE path behind ``POST /targets/{id}/attest``.
  It loads the target, enforces the per-method attestation minimums server-side
  (never trusting the client), flips it to ``ATTESTED`` (recording method /
  principal / evidence / expiry), and appends a ``TARGET_ATTESTED`` row to the
  append-only, hash-chained audit log via :func:`app.audit.writer.record_event`.
  It does **not** commit — the route owns the transaction (see ``app.api.targets``).

Dependency direction (no cycles): authz.attestation -> {audit.writer, core.errors,
models.audit, models.target}. It never imports authz.gate / scope / dto / errors,
nor services / api.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.writer import record_event
from app.core.errors import NotFoundError, ValidationAppError
from app.models.audit import AuditAction
from app.models.target import AttestationMethod, AttestationStatus, AuthorizedTarget

if TYPE_CHECKING:  # pragma: no cover - typing only; never imported at runtime
    from app.auth.sso import AuthUser

__all__ = ["attestation_is_valid", "attest_target"]

# Ownership-proof methods (external targets): the operator must supply evidence.
_PROOF_METHODS = frozenset(
    {
        AttestationMethod.DNS_TXT,
        AttestationMethod.FILE_DROP,
        AttestationMethod.HTTP_HEADER,
    }
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    """Coerce a possibly-naive timestamp to timezone-aware UTC for safe compares."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


# ---------------------------------------------------------------------------
# The pure predicate (gate hot path)
# ---------------------------------------------------------------------------
def attestation_is_valid(target: Any, *, now: datetime | None = None) -> bool:
    """Whether ``target``'s attestation authorizes a scan at ``now`` (default: now).

    True iff the target is currently ``ATTESTED`` and is neither revoked
    (``revoked_at`` set and in the past) nor expired (``expires_at`` set and in the
    past). Belt-and-suspenders: the revoked/expired checks hold even if a stale
    ``ATTESTED`` status lingers, which is exactly how the gate distinguishes an
    ``attestation_expired`` denial from ``target_not_attested``.
    """
    if target is None:
        return False
    if getattr(target, "attestation_status", None) != AttestationStatus.ATTESTED:
        return False
    moment = _aware(now) or _utcnow()
    revoked_at = _aware(getattr(target, "revoked_at", None))
    if revoked_at is not None and revoked_at <= moment:
        return False
    expires_at = _aware(getattr(target, "expires_at", None))
    if expires_at is not None and expires_at <= moment:
        return False
    return True


# ---------------------------------------------------------------------------
# The write path (POST /targets/{id}/attest)
# ---------------------------------------------------------------------------
async def attest_target(
    session: AsyncSession,
    target_id: uuid.UUID,
    *,
    principal: "AuthUser | str",
    method: AttestationMethod | str,
    checkbox_ack: bool = False,
    typed_confirmation: str | None = None,
    evidence: dict[str, Any] | None = None,
    expires_at: datetime | None = None,
) -> AuthorizedTarget:
    """Attest ``target_id`` so the gate will treat it as scannable, and audit it.

    Enforces the attestation minimums (spec §4) SERVER-SIDE:

    * every method except ``OWNED`` requires an explicit ``checkbox_ack``;
    * ``TYPED_CONFIRMATION`` additionally requires a non-empty ``typed_confirmation``;
    * the ownership-proof methods (``DNS_TXT`` / ``FILE_DROP`` / ``HTTP_HEADER``)
      require ``evidence`` (the proof payload is recorded; live proof verification
      is Phase 3);
    * a supplied ``expires_at`` must be in the future.

    On success it sets status ``ATTESTED`` (clearing any prior revocation/expiry),
    records who/when/how, appends exactly one ``TARGET_ATTESTED`` audit row, and
    returns the (uncommitted) target. Raises :class:`ValidationAppError` (422) on a
    failed minimum and :class:`NotFoundError` (404) if the target is gone. The
    caller owns the commit.
    """
    target = await session.get(AuthorizedTarget, target_id)
    if target is None:
        raise NotFoundError("Target not found")

    method = _coerce_method(method)
    _enforce_minimums(method, checkbox_ack, typed_confirmation, evidence, expires_at)

    now = _utcnow()
    target.attestation_status = AttestationStatus.ATTESTED
    target.attestation_method = method
    target.attested_by = _principal_ref(principal)
    target.attested_at = now
    if evidence is not None:
        target.attestation_evidence = evidence
    target.expires_at = expires_at
    target.revoked_at = None

    # Persist the mutation before the audit append so any DB error surfaces here;
    # the route owns the commit (no commit in this function).
    await session.flush()

    await record_event(
        session,
        action=AuditAction.TARGET_ATTESTED,
        actor=principal,
        org_id=target.org_id,
        engagement_id=None,
        run_id=None,
        target=target.value,
        target_id=target.id,
        decision="allow",
        reason=f"target attested via {method.value}",
        detail={
            "method": method.value,
            "checkbox_ack": bool(checkbox_ack),
            "typed_confirmation": bool((typed_confirmation or "").strip()),
            "expires_at": expires_at.isoformat() if isinstance(expires_at, datetime) else None,
            "evidence_keys": sorted(evidence) if isinstance(evidence, dict) else None,
        },
    )
    return target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _enforce_minimums(
    method: AttestationMethod,
    checkbox_ack: bool,
    typed_confirmation: str | None,
    evidence: dict[str, Any] | None,
    expires_at: datetime | None,
) -> None:
    if method != AttestationMethod.OWNED and not checkbox_ack:
        raise ValidationAppError(
            "attestation requires an explicit checkbox acknowledgement",
            code="attestation_incomplete",
            detail={"field": "checkbox_ack", "method": method.value},
        )
    if method == AttestationMethod.TYPED_CONFIRMATION and not (typed_confirmation or "").strip():
        raise ValidationAppError(
            "typed confirmation is required for TYPED_CONFIRMATION attestation",
            code="attestation_incomplete",
            detail={"field": "typed_confirmation"},
        )
    if method in _PROOF_METHODS and not evidence:
        raise ValidationAppError(
            f"{method.value} attestation requires ownership-proof evidence",
            code="attestation_incomplete",
            detail={"field": "evidence", "method": method.value},
        )
    if expires_at is not None and (_aware(expires_at) or _utcnow()) <= _utcnow():
        raise ValidationAppError(
            "attestation expiry must be in the future",
            code="attestation_expiry_invalid",
            detail={"field": "expires_at"},
        )


def _coerce_method(method: AttestationMethod | str | None) -> AttestationMethod:
    if isinstance(method, AttestationMethod):
        return method
    if method is None:
        raise ValidationAppError(
            "attestation method is required",
            code="attestation_incomplete",
            detail={"field": "method"},
        )
    raw = str(method).strip()
    try:
        return AttestationMethod(raw)  # by value
    except ValueError:
        pass
    try:
        return AttestationMethod[raw.upper()]  # by name
    except KeyError as exc:
        raise ValidationAppError(
            f"unknown attestation method: {method!r}",
            code="attestation_invalid",
            detail={"field": "method"},
        ) from exc


def _principal_ref(principal: "AuthUser | str | None") -> str:
    """A stable string id for the ``attested_by`` column."""
    if principal is None:
        return "unknown"
    if isinstance(principal, str):
        return principal
    ref = getattr(principal, "id", None) or getattr(principal, "email", None)
    return str(ref) if ref else str(principal)
