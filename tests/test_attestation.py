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
from app.core.errors import ValidationAppError
from app.models.target import AttestationMethod, AttestationStatus
from tests.conftest import make_org, make_target, utcnow


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
