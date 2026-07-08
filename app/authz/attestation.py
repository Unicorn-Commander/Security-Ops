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
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.writer import record_event
from app.authz.proof import ProofResult, is_proof_method, verify_proof
from app.core.config import settings
from app.core.errors import ForbiddenError, NotFoundError, ValidationAppError
from app.models.audit import AuditAction
from app.models.target import AttestationMethod, AttestationStatus, AuthorizedTarget

if TYPE_CHECKING:  # pragma: no cover - typing only; never imported at runtime
    from app.auth.sso import AuthUser

__all__ = ["attestation_is_valid", "attest_target"]

# Ownership-proof methods (external targets): the operator must supply evidence
# AND the server independently verifies a live ownership proof (app.authz.proof).
_PROOF_METHODS = frozenset(
    {
        AttestationMethod.DNS_TXT,
        AttestationMethod.FILE_DROP,
        AttestationMethod.HTTP_HEADER,
    }
)

# Admin-only "authorized-operator" methods: no live ownership proof; authorization
# is a RECORDED human decision (justification + acknowledgement), still time-boxed
# and audited. See AttestationMethod docstring and settings.attestation_allow_*.
_PRIVILEGED_METHODS = frozenset(
    {
        AttestationMethod.SELF_ATTESTED,
        AttestationMethod.BREAK_GLASS,
    }
)

# Methods that must always carry an expiry (external + break-glass grants never
# become standing access): a default TTL is applied when the caller supplies none.
_EXPIRING_METHODS = _PROOF_METHODS | _PRIVILEGED_METHODS

#: Signature of an injectable proof verifier (defaults to the live verifier).
ProofVerifier = Callable[[AuthorizedTarget, AttestationMethod], ProofResult]


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
    justification: str | None = None,
    evidence: dict[str, Any] | None = None,
    expires_at: datetime | None = None,
    verifier: ProofVerifier | None = None,
    actor_is_admin: bool = False,
) -> AuthorizedTarget:
    """Attest ``target_id`` so the gate will treat it as scannable, and audit it.

    Enforces the attestation minimums (spec §4) SERVER-SIDE:

    * every method except ``OWNED`` requires an explicit ``checkbox_ack``;
    * ``TYPED_CONFIRMATION`` additionally requires a non-empty ``typed_confirmation``;
    * the ownership-proof methods (``DNS_TXT`` / ``FILE_DROP`` / ``HTTP_HEADER``)
      are **verified live** against the asset (:mod:`app.authz.proof`): the server
      re-derives the per-target challenge token and confirms the operator actually
      published it (DNS TXT record / well-known file / ``Strix-Authorization``
      header). A proof that does not resolve raises 422 and the target stays
      unattested — a scan therefore remains impossible. (Set
      ``settings.attestation_skip_live_proof`` only in air-gapped/test envs.)
    * a supplied ``expires_at`` must be in the future; for external-proof methods a
      default lifetime (``settings.attestation_default_ttl_days``) is applied when
      none is given, so external authorizations always expire.
    * the admin-only ``SELF_ATTESTED`` / ``BREAK_GLASS`` methods skip the live proof
      in favor of a recorded human authorization: they require ``actor_is_admin``
      (and, for break-glass, the ``attestation_allow_break_glass`` install switch),
      a written ``justification``, and are time-boxed (break-glass on the shorter
      ``attestation_break_glass_ttl_days``). Break-glass is recorded under its own
      ``TARGET_BREAK_GLASS`` audit action. This removes the ownership-proof
      *friction* for authorized red-team / DFIR work while preserving the audit
      trail that makes that work accountable. Raises :class:`ForbiddenError` (403)
      if the caller may not use the method.

    On success it sets status ``ATTESTED`` (clearing any prior revocation/expiry),
    records who/when/how + the live proof result, appends exactly one
    ``TARGET_ATTESTED`` audit row, and returns the (uncommitted) target. Raises
    :class:`ValidationAppError` (422) on a failed minimum or unmet proof, and
    :class:`NotFoundError` (404) if the target is gone. The caller owns the commit.

    ``verifier`` is injectable (tests / alternate transports); it defaults to the
    live :func:`app.authz.proof.verify_proof`.
    """
    target = await session.get(AuthorizedTarget, target_id)
    if target is None:
        raise NotFoundError("Target not found")

    method = _coerce_method(method)
    # Admin-only break-glass / self-attest paths are authorized (role + install
    # switch) BEFORE any minimums are checked, so an unprivileged caller learns
    # only that the method is unavailable, never how to satisfy it.
    if method in _PRIVILEGED_METHODS:
        _authorize_privileged_method(method, actor_is_admin)
    _enforce_minimums(
        method, checkbox_ack, typed_confirmation, justification, evidence, expires_at
    )

    # External-target ownership proof — VERIFIED live, not merely recorded.
    # Privileged methods (self-attest / break-glass) deliberately skip this: their
    # authorization is the recorded human decision, not a live network proof.
    proof_evidence: dict[str, Any] | None = None
    if is_proof_method(method):
        proof_evidence = _verify_ownership_proof(target, method, verifier)

    now = _utcnow()
    effective_expiry = _effective_expiry(method, expires_at, now)
    is_break_glass = method == AttestationMethod.BREAK_GLASS

    target.attestation_status = AttestationStatus.ATTESTED
    target.attestation_method = method
    target.attested_by = _principal_ref(principal)
    target.attested_at = now
    merged_evidence = _merge_evidence(evidence, proof_evidence, method, justification)
    if merged_evidence is not None:
        target.attestation_evidence = merged_evidence
    target.expires_at = effective_expiry
    target.revoked_at = None

    # Persist the mutation before the audit append so any DB error surfaces here;
    # the route owns the commit (no commit in this function).
    await session.flush()

    # Break-glass gets its own audit action so every emergency grant is trivially
    # alertable ("who used god-mode, when, why"); everything else stays TARGET_ATTESTED.
    action = AuditAction.TARGET_BREAK_GLASS if is_break_glass else AuditAction.TARGET_ATTESTED
    reason = (
        f"BREAK-GLASS authorization (no ownership proof) via {method.value}"
        if is_break_glass
        else f"target attested via {method.value}"
    )
    await record_event(
        session,
        action=action,
        actor=principal,
        org_id=target.org_id,
        engagement_id=None,
        run_id=None,
        target=target.value,
        target_id=target.id,
        decision="allow",
        reason=reason,
        detail={
            "method": method.value,
            "checkbox_ack": bool(checkbox_ack),
            "typed_confirmation": bool((typed_confirmation or "").strip()),
            "justification": (justification or "").strip() or None,
            "privileged": method in _PRIVILEGED_METHODS,
            "break_glass": is_break_glass,
            "authorized_by_admin": bool(actor_is_admin) if method in _PRIVILEGED_METHODS else None,
            "expires_at": effective_expiry.isoformat() if isinstance(effective_expiry, datetime) else None,
            "evidence_keys": sorted(merged_evidence) if isinstance(merged_evidence, dict) else None,
            "proof_verified": bool(proof_evidence and proof_evidence.get("verified")),
        },
    )
    return target


def _authorize_privileged_method(method: AttestationMethod, actor_is_admin: bool) -> None:
    """Gate the admin-only attestation paths: role + (for break-glass) install switch.

    Raises :class:`ForbiddenError` (403) — an authorization failure, distinct from a
    422 "you filled the form out wrong" — when the caller may not use this method:

    * ``SELF_ATTESTED`` requires ``settings.attestation_allow_self_attest`` (on by
      default) AND an org-ADMIN caller.
    * ``BREAK_GLASS`` additionally requires the install-time
      ``settings.attestation_allow_break_glass`` switch to be enabled.

    Because MCP PAT principals resolve to OPERATOR (never ADMIN), a leaked token can
    never reach these paths — god-mode is only available to an interactive admin.
    """
    if method == AttestationMethod.SELF_ATTESTED and not settings.attestation_allow_self_attest:
        raise ForbiddenError(
            "self-attestation is disabled on this deployment",
            code="attestation_method_disabled",
            detail={"method": method.value},
        )
    if method == AttestationMethod.BREAK_GLASS and not settings.attestation_allow_break_glass:
        raise ForbiddenError(
            "break-glass attestation is not enabled on this deployment",
            code="attestation_method_disabled",
            detail={"method": method.value, "enable_with": "attestation_allow_break_glass"},
        )
    if not actor_is_admin:
        raise ForbiddenError(
            f"{method.value} attestation requires an organization admin",
            code="attestation_admin_required",
            detail={"method": method.value},
        )


def _verify_ownership_proof(
    target: AuthorizedTarget,
    method: AttestationMethod,
    verifier: ProofVerifier | None,
) -> dict[str, Any]:
    """Run (or skip) the live ownership proof; raise 422 if it does not verify.

    Returns the proof evidence dict to persist. When
    ``settings.attestation_skip_live_proof`` is set (air-gapped / test), the live
    check is bypassed and a ``skipped`` evidence marker is recorded instead — this
    switch must NEVER be enabled in production.
    """
    if settings.attestation_skip_live_proof:
        return {"verified": True, "method": method.value, "proof": "skipped_live_verification"}

    verify = verifier or verify_proof
    result = verify(target, method)
    evidence = result.as_evidence() if isinstance(result, ProofResult) else dict(result)
    if not evidence.get("verified"):
        raise ValidationAppError(
            f"ownership proof for {method.value} did not verify against {target.value!r}",
            code="attestation_proof_failed",
            detail={
                "method": method.value,
                "target": target.value,
                "expected_token": evidence.get("token"),
                "location": evidence.get("location"),
            },
        )
    return evidence


def _effective_expiry(
    method: AttestationMethod, expires_at: datetime | None, now: datetime
) -> datetime | None:
    """Apply a default lifetime for methods that must always expire.

    External-proof and privileged (self-attest / break-glass) grants never become
    standing access: when no explicit expiry is supplied a default TTL is applied.
    Break-glass uses the deliberately shorter ``attestation_break_glass_ttl_days``.
    """
    if expires_at is not None:
        return expires_at
    if method == AttestationMethod.BREAK_GLASS:
        days = max(int(settings.attestation_break_glass_ttl_days or 0), 1)
        return now + timedelta(days=days)
    if method in _EXPIRING_METHODS:
        days = max(int(settings.attestation_default_ttl_days or 0), 1)
        return now + timedelta(days=days)
    return None


def _merge_evidence(
    supplied: dict[str, Any] | None,
    proof: dict[str, Any] | None,
    method: AttestationMethod | None = None,
    justification: str | None = None,
) -> dict[str, Any] | None:
    """Combine operator evidence, the live-proof record, and the privileged-grant
    justification into the persisted evidence blob.

    For a self-attest / break-glass grant the recorded ``authorization`` block IS
    the accountability artifact (there is no ownership proof), so the justification
    text and method label are always captured.
    """
    justification = (justification or "").strip()
    is_privileged = method in _PRIVILEGED_METHODS
    if supplied is None and proof is None and not (is_privileged and justification):
        return None
    merged: dict[str, Any] = dict(supplied or {})
    if proof is not None:
        merged["ownership_proof"] = proof
    if is_privileged:
        merged["authorization"] = {
            "method": method.value,
            "basis": justification or None,
            "ownership_proof": False,
        }
    return merged


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _enforce_minimums(
    method: AttestationMethod,
    checkbox_ack: bool,
    typed_confirmation: str | None,
    justification: str | None,
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
    # Privileged (self-attest / break-glass) grants have no ownership proof, so the
    # written justification IS the authorization record — it is mandatory. A short
    # floor prevents an empty "." from standing in for a real basis.
    if method in _PRIVILEGED_METHODS and len((justification or "").strip()) < 8:
        raise ValidationAppError(
            "a written authorization justification (min 8 chars) is required for "
            f"{method.value} attestation",
            code="attestation_incomplete",
            detail={"field": "justification", "method": method.value},
        )
    # NOTE: ownership-proof methods no longer require operator-supplied evidence —
    # the server derives its own per-target challenge token and VERIFIES the proof
    # live (see attest_target -> _verify_ownership_proof), which is strictly
    # stronger than trusting a client-provided evidence blob.
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
