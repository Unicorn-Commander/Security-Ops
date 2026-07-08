"""Attestation predicate + write-path minimums (spec §4).

``attestation_is_valid`` is the gate's hot-path predicate; ``attest_target``
enforces the per-method minimums server-side (never trusting the client). Live
external-proof verification (DNS-TXT / file-drop / header) is covered in
tests/test_proof.py — here we pin the status/expiry/revocation logic and the
minimum-acknowledgement rules.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.authz.attestation import attest_target, attestation_is_valid
from app.core.config import get_settings
from app.core.errors import ForbiddenError, ValidationAppError
from app.models.audit import AuditAction, AuditEvent
from app.models.target import AttestationMethod, AttestationStatus
from tests.conftest import make_org, make_target, utcnow
from sqlalchemy import select


# ---------------------------------------------------------------------------
# The pure predicate
# ---------------------------------------------------------------------------
class _T:
    """Minimal duck-typed target for the predicate."""

    def __init__(self, status, expires_at=None, revoked_at=None):
        self.attestation_status = status
        self.expires_at = expires_at
        self.revoked_at = revoked_at


def test_attested_and_unexpired_is_valid():
    assert attestation_is_valid(_T(AttestationStatus.ATTESTED)) is True
    assert attestation_is_valid(_T(AttestationStatus.ATTESTED, expires_at=utcnow() + timedelta(days=1))) is True


def test_unattested_is_invalid():
    assert attestation_is_valid(_T(AttestationStatus.UNATTESTED)) is False
    assert attestation_is_valid(None) is False


def test_expired_is_invalid():
    assert attestation_is_valid(_T(AttestationStatus.ATTESTED, expires_at=utcnow() - timedelta(seconds=1))) is False


def test_revoked_is_invalid():
    assert attestation_is_valid(_T(AttestationStatus.ATTESTED, revoked_at=utcnow() - timedelta(seconds=1))) is False


# ---------------------------------------------------------------------------
# The write path minimums
# ---------------------------------------------------------------------------
async def test_owned_attestation_succeeds_with_checkbox(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    result = await attest_target(
        db_session, t.id, principal="tester", method=AttestationMethod.OWNED, checkbox_ack=True
    )
    assert result.attestation_status == AttestationStatus.ATTESTED
    assert result.attestation_method == AttestationMethod.OWNED


async def test_non_owned_requires_checkbox(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    with pytest.raises(ValidationAppError):
        await attest_target(
            db_session, t.id, principal="tester",
            method=AttestationMethod.TYPED_CONFIRMATION, checkbox_ack=False,
            typed_confirmation="I own this",
        )


async def test_typed_confirmation_requires_text(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    with pytest.raises(ValidationAppError):
        await attest_target(
            db_session, t.id, principal="tester",
            method=AttestationMethod.TYPED_CONFIRMATION, checkbox_ack=True,
            typed_confirmation="   ",
        )


async def test_past_expiry_is_rejected(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    with pytest.raises(ValidationAppError):
        await attest_target(
            db_session, t.id, principal="tester", method=AttestationMethod.OWNED,
            checkbox_ack=True, expires_at=utcnow() - timedelta(days=1),
        )


# ---------------------------------------------------------------------------
# Admin-only break-glass / self-attest methods (spec §4 break-glass extension)
# ---------------------------------------------------------------------------
async def test_self_attest_requires_admin(db_session):
    """A non-admin caller is refused (403), never told how to satisfy the method."""
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    with pytest.raises(ForbiddenError):
        await attest_target(
            db_session, t.id, principal="tester",
            method=AttestationMethod.SELF_ATTESTED, checkbox_ack=True,
            justification="we own this box", actor_is_admin=False,
        )


async def test_self_attest_requires_justification(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    with pytest.raises(ValidationAppError):
        await attest_target(
            db_session, t.id, principal="admin",
            method=AttestationMethod.SELF_ATTESTED, checkbox_ack=True,
            justification="short", actor_is_admin=True,
        )


async def test_self_attest_admin_succeeds_and_expires(db_session):
    """SELF_ATTESTED flips ATTESTED, records the basis, and always gets an expiry."""
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    result = await attest_target(
        db_session, t.id, principal="admin",
        method=AttestationMethod.SELF_ATTESTED, checkbox_ack=True,
        justification="Owned infra: internal staging cluster, ticket OPS-1421",
        actor_is_admin=True,
    )
    assert result.attestation_status == AttestationStatus.ATTESTED
    assert result.attestation_method == AttestationMethod.SELF_ATTESTED
    assert result.expires_at is not None  # never standing access
    assert result.attestation_evidence["authorization"]["ownership_proof"] is False
    # Self-attest is a normal (non-break-glass) attestation audit action.
    row = (
        await db_session.execute(
            select(AuditEvent).where(AuditEvent.target_id == t.id)
        )
    ).scalar_one()
    assert row.action == AuditAction.TARGET_ATTESTED
    assert row.detail["privileged"] is True
    assert row.detail["break_glass"] is False


async def test_break_glass_disabled_by_default(db_session):
    """Break-glass is refused until the install switch is enabled — even for admins."""
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    assert get_settings().attestation_allow_break_glass is False
    with pytest.raises(ForbiddenError):
        await attest_target(
            db_session, t.id, principal="admin",
            method=AttestationMethod.BREAK_GLASS, checkbox_ack=True,
            justification="DFIR: contain compromised host per IR-77",
            actor_is_admin=True,
        )


async def test_break_glass_when_enabled_audits_distinctly(db_session, monkeypatch):
    """Enabled + admin + justification -> ATTESTED, short TTL, TARGET_BREAK_GLASS audit."""
    monkeypatch.setattr(get_settings(), "attestation_allow_break_glass", True)
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    result = await attest_target(
        db_session, t.id, principal="admin",
        method=AttestationMethod.BREAK_GLASS, checkbox_ack=True,
        justification="DFIR: contain compromised host per IR-77",
        actor_is_admin=True,
    )
    assert result.attestation_status == AttestationStatus.ATTESTED
    assert result.attestation_method == AttestationMethod.BREAK_GLASS
    # Break-glass TTL (7d) is shorter than the external-proof default (90d).
    assert result.expires_at is not None
    assert result.expires_at <= utcnow() + timedelta(days=8)
    row = (
        await db_session.execute(
            select(AuditEvent).where(AuditEvent.target_id == t.id)
        )
    ).scalar_one()
    assert row.action == AuditAction.TARGET_BREAK_GLASS
    assert row.detail["break_glass"] is True
    assert row.detail["justification"] == "DFIR: contain compromised host per IR-77"
    assert row.decision == "allow"


async def test_break_glass_still_requires_admin_when_enabled(db_session, monkeypatch):
    monkeypatch.setattr(get_settings(), "attestation_allow_break_glass", True)
    org = await make_org(db_session)
    t = await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    with pytest.raises(ForbiddenError):
        await attest_target(
            db_session, t.id, principal="tester",
            method=AttestationMethod.BREAK_GLASS, checkbox_ack=True,
            justification="DFIR: contain compromised host per IR-77",
            actor_is_admin=False,
        )
