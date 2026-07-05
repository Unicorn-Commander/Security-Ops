"""Live external-target ownership-proof verification (spec §4).

The gate is only as trustworthy as its attestations. For external targets the
server must PROVE the operator controls the asset — a checkbox is not enough.
These tests pin: the challenge token is unpredictable + stable, each verifier
matches a published token (and rejects a missing/wrong one), and ``attest_target``
refuses to attest a proof method whose proof does not resolve (so the gate can
never authorize an unproven external target).

Verifiers are exercised with INJECTED resolver/fetch callables — no network, no
optional DNS dependency.
"""

from __future__ import annotations

import uuid

import pytest

from app.authz import proof
from app.authz.attestation import attest_target
from app.authz.proof import (
    ProofResult,
    challenge_token,
    proof_instructions,
    verify_dns_txt,
    verify_file_drop,
    verify_http_header,
)
from app.core.config import get_settings
from app.core.errors import ValidationAppError
from app.models.target import AttestationMethod, AttestationStatus, TargetKind
from tests.conftest import make_org, make_target


# ---------------------------------------------------------------------------
# Challenge token
# ---------------------------------------------------------------------------
def test_challenge_token_is_stable_and_bound_to_target():
    class _T:
        id = uuid.UUID("00000000-0000-0000-0000-0000000000aa")

    t = _T()
    tok = challenge_token(t)
    assert tok == challenge_token(t)  # stable
    assert str(t.id) in tok
    assert tok.startswith("security-ops-site-verification=")


# ---------------------------------------------------------------------------
# Verifiers with injected resolver / fetch
# ---------------------------------------------------------------------------
async def test_dns_txt_verifies_when_token_published(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, value="acme.example", status=AttestationStatus.UNATTESTED)
    token = challenge_token(t)

    good = verify_dns_txt(t, resolver=lambda name: ["some-other=1", token])
    assert good.verified is True
    assert good.location.endswith("acme.example")

    bad = verify_dns_txt(t, resolver=lambda name: ["unrelated-record"])
    assert bad.verified is False


async def test_file_drop_verifies_from_body(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, value="https://acme.example", status=AttestationStatus.UNATTESTED)
    token = challenge_token(t)

    good = verify_file_drop(t, fetch=lambda url: (f"\n{token}\n", {}))
    assert good.verified is True

    bad = verify_file_drop(t, fetch=lambda url: ("404 not found", {}))
    assert bad.verified is False


async def test_http_header_verifies_case_insensitively(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, value="acme.example", status=AttestationStatus.UNATTESTED)
    token = challenge_token(t)

    good = verify_http_header(t, fetch=lambda url: ("", {"strix-authorization": token}))
    assert good.verified is True

    bad = verify_http_header(t, fetch=lambda url: ("", {"x-other": "nope"}))
    assert bad.verified is False


def test_proof_instructions_cover_all_three_methods():
    class _T:
        id = uuid.uuid4()
        value = "acme.example"

    instr = proof_instructions(_T())
    methods = instr["methods"]
    assert set(methods) == {"DNS_TXT", "FILE_DROP", "HTTP_HEADER"}
    assert instr["token"] in methods["DNS_TXT"]["value"]


# ---------------------------------------------------------------------------
# attest_target: proof methods must verify LIVE before the gate trusts them.
# ---------------------------------------------------------------------------
async def test_attest_proof_method_requires_live_verification(db_session, monkeypatch):
    # Turn OFF the test-only skip so real verification runs (via injected verifier).
    monkeypatch.setattr(get_settings(), "attestation_skip_live_proof", False)

    org = await make_org(db_session)
    t = await make_target(
        db_session, org, value="external.example", kind=TargetKind.DOMAIN,
        status=AttestationStatus.UNATTESTED,
    )

    # A verifier that reports the proof did NOT resolve -> attestation refused.
    def failing(target, method):
        return ProofResult(verified=False, method=method, token=challenge_token(target), location="x")

    with pytest.raises(ValidationAppError) as ei:
        await attest_target(
            db_session, t.id, principal="tester",
            method=AttestationMethod.DNS_TXT, checkbox_ack=True, verifier=failing,
        )
    assert ei.value.code == "attestation_proof_failed"

    await db_session.refresh(t)
    assert t.attestation_status == AttestationStatus.UNATTESTED  # still not scannable


async def test_attest_proof_method_succeeds_when_verified(db_session, monkeypatch):
    monkeypatch.setattr(get_settings(), "attestation_skip_live_proof", False)

    org = await make_org(db_session)
    t = await make_target(
        db_session, org, value="external.example", kind=TargetKind.DOMAIN,
        status=AttestationStatus.UNATTESTED,
    )

    def passing(target, method):
        return ProofResult(verified=True, method=method, token=challenge_token(target), location="dns")

    result = await attest_target(
        db_session, t.id, principal="tester",
        method=AttestationMethod.DNS_TXT, checkbox_ack=True, verifier=passing,
    )
    assert result.attestation_status == AttestationStatus.ATTESTED
    # External proof gets a default expiry so it can't be permanent.
    assert result.expires_at is not None
    assert result.attestation_evidence["ownership_proof"]["verified"] is True


async def test_skip_live_proof_bypasses_network(db_session, monkeypatch):
    # The default test env sets attestation_skip_live_proof=true; verify it attests
    # without any verifier being called (air-gapped/dev path).
    monkeypatch.setattr(get_settings(), "attestation_skip_live_proof", True)

    org = await make_org(db_session)
    t = await make_target(
        db_session, org, value="external.example", status=AttestationStatus.UNATTESTED,
    )

    def exploding(target, method):  # must NOT be called
        raise AssertionError("verifier should be skipped")

    result = await attest_target(
        db_session, t.id, principal="tester",
        method=AttestationMethod.FILE_DROP, checkbox_ack=True, verifier=exploding,
    )
    assert result.attestation_status == AttestationStatus.ATTESTED
