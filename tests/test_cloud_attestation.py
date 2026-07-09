"""CLOUD_ACCOUNT target kind + CLOUD_ROLE possession-proof attestation (spec §4, Prowler).

The cloud proof is the one attestation whose authorization is an assumed-role identity
rather than a published token. These tests pin: the external-ID challenge derivation, the
role-assumption verifier (success / denied / account-mismatch / skip), the attest write
path (success + evidence + audit, missing-role 422, failed-proof stays unattested,
disabled-switch 403), and the end-to-end gate decision over a cloud target.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.authz.attestation import attest_target, attestation_is_valid
from app.authz.cloud_proof import (
    CloudProofResult,
    cloud_external_id,
    cloud_instructions,
    parse_cloud_value,
    verify_cloud_role,
)
from app.authz.gate import enforce_scope, check_scope
from app.authz.scope import normalize_target, target_covers
from app.core.config import get_settings
from app.core.errors import ForbiddenError, ValidationAppError
from app.models.audit import AuditAction, AuditEvent
from app.models.target import AttestationMethod, AttestationStatus, AuthorizedTarget, TargetKind
from tests.conftest import make_engagement, make_org, make_target, utcnow

AWS_ACCT = "aws:123456789012"
ROLE_ARN = "arn:aws:iam::123456789012:role/SecurityOpsScanner"


class _FakeTarget:
    def __init__(self, tid: str = "t-1", value: str = AWS_ACCT):
        self.id = tid
        self.value = value


# ---------------------------------------------------------------------------
# Challenge + value parsing + instructions
# ---------------------------------------------------------------------------
def test_external_id_is_derived_from_target_id():
    tok = cloud_external_id(_FakeTarget("abc-123"))
    assert tok == "security-ops-external-id=abc-123"


def test_parse_cloud_value():
    assert parse_cloud_value("aws:123456789012") == ("aws", "123456789012")
    assert parse_cloud_value("GCP:my-project") == ("gcp", "my-project")
    with pytest.raises(ValueError):
        parse_cloud_value("example.com")


def test_cloud_instructions_bind_external_id_into_trust_policy():
    instr = cloud_instructions(_FakeTarget("xyz"))
    assert instr["method"] == "CLOUD_ROLE"
    assert instr["external_id"] == "security-ops-external-id=xyz"
    # The AWS trust-policy snippet must require OUR external ID (confused-deputy safe).
    cond = instr["aws_trust_policy"]["Statement"][0]["Condition"]["StringEquals"]
    assert cond["sts:ExternalId"] == "security-ops-external-id=xyz"


# ---------------------------------------------------------------------------
# The live verifier (injected assume_role)
# ---------------------------------------------------------------------------
def test_verify_cloud_role_success_records_assumed_identity(monkeypatch):
    monkeypatch.setattr(get_settings(), "attestation_skip_live_proof", False)
    t = _FakeTarget()
    captured = {}

    def fake_assume(role_arn, external_id, region):
        captured["role_arn"] = role_arn
        captured["external_id"] = external_id
        return {"arn": "arn:aws:sts::123456789012:assumed-role/SecurityOpsScanner/sess", "account": "123456789012"}

    res = verify_cloud_role(t, role_arn=ROLE_ARN, assume_role=fake_assume)
    assert res.verified is True
    assert res.assumed_identity.startswith("arn:aws:sts::123456789012:assumed-role/")
    # The verifier must pass OUR derived external ID to the assume-role call.
    assert captured["external_id"] == cloud_external_id(t)
    assert res.as_evidence()["assumed_identity"] == res.assumed_identity


def test_verify_cloud_role_denied_is_unverified_not_raised(monkeypatch):
    monkeypatch.setattr(get_settings(), "attestation_skip_live_proof", False)
    # An empty identity == the operator's trust policy did not let us in (bad/no
    # external id, principal not trusted) — an UNMET proof, not a crash.
    res = verify_cloud_role(_FakeTarget(), role_arn=ROLE_ARN, assume_role=lambda *a: {})
    assert res.verified is False


def test_verify_cloud_role_rejects_role_in_other_account():
    # role ARN account (999...) != attested account (123...) => refuse before assuming.
    res = verify_cloud_role(
        _FakeTarget(value="aws:123456789012"),
        role_arn="arn:aws:iam::999999999999:role/Evil",
        assume_role=lambda *a: {"arn": "x", "account": "999999999999"},
    )
    assert res.verified is False
    assert "account" in (res.detail.get("error") or "")


def test_verify_cloud_role_rejects_missing_role_arn():
    assert verify_cloud_role(_FakeTarget(), role_arn="", assume_role=lambda *a: {"arn": "x"}).verified is False


def test_verify_cloud_role_skip_live_proof(monkeypatch):
    monkeypatch.setattr(get_settings(), "attestation_skip_live_proof", True)
    called = {"n": 0}

    def should_not_call(*a):  # pragma: no cover - asserted not called
        called["n"] += 1
        return {}

    res = verify_cloud_role(_FakeTarget(), role_arn=ROLE_ARN, assume_role=should_not_call)
    assert res.verified is True
    assert called["n"] == 0  # skip means no live STS call


# ---------------------------------------------------------------------------
# attest_target write path
# ---------------------------------------------------------------------------
def _ok_verifier(target, *, role_arn, region=None):
    return CloudProofResult(
        verified=True,
        method=AttestationMethod.CLOUD_ROLE,
        external_id=cloud_external_id(target),
        role_arn=role_arn,
        provider="aws",
        account="123456789012",
        assumed_identity="arn:aws:sts::123456789012:assumed-role/SecurityOpsScanner/s",
        observed_account="123456789012",
    )


async def test_attest_cloud_role_success(db_session):
    org = await make_org(db_session)
    t = await make_target(
        db_session, org, value=AWS_ACCT, kind=TargetKind.CLOUD_ACCOUNT,
        status=AttestationStatus.UNATTESTED,
    )
    result = await attest_target(
        db_session, t.id, principal="tester", method=AttestationMethod.CLOUD_ROLE,
        checkbox_ack=True, evidence={"role_arn": ROLE_ARN, "region": "us-east-1"},
        cloud_verifier=_ok_verifier,
    )
    assert result.attestation_status == AttestationStatus.ATTESTED
    assert result.attestation_method == AttestationMethod.CLOUD_ROLE
    assert result.expires_at is not None  # cloud grants are time-boxed
    assert result.attestation_evidence["cloud_authorization"]["assumed_identity"]
    # exactly one TARGET_ATTESTED audit row
    rows = (await db_session.execute(select(AuditEvent).where(AuditEvent.action == AuditAction.TARGET_ATTESTED))).scalars().all()
    assert len(rows) == 1


async def test_attest_cloud_role_requires_role_arn(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, value=AWS_ACCT, kind=TargetKind.CLOUD_ACCOUNT, status=AttestationStatus.UNATTESTED)
    with pytest.raises(ValidationAppError):
        await attest_target(
            db_session, t.id, principal="tester", method=AttestationMethod.CLOUD_ROLE,
            checkbox_ack=True, evidence={}, cloud_verifier=_ok_verifier,
        )


async def test_attest_cloud_role_failed_proof_stays_unattested(db_session):
    org = await make_org(db_session)
    t = await make_target(db_session, org, value=AWS_ACCT, kind=TargetKind.CLOUD_ACCOUNT, status=AttestationStatus.UNATTESTED)

    def deny(target, *, role_arn, region=None):
        return CloudProofResult(False, AttestationMethod.CLOUD_ROLE, cloud_external_id(target), role_arn, "aws", "123456789012", detail={"error": "denied"})

    with pytest.raises(ValidationAppError):
        await attest_target(
            db_session, t.id, principal="tester", method=AttestationMethod.CLOUD_ROLE,
            checkbox_ack=True, evidence={"role_arn": ROLE_ARN}, cloud_verifier=deny,
        )
    refreshed = await db_session.get(AuthorizedTarget, t.id)
    assert refreshed.attestation_status == AttestationStatus.UNATTESTED


async def test_attest_cloud_role_disabled_switch_forbidden(db_session, monkeypatch):
    monkeypatch.setattr(get_settings(), "attestation_allow_cloud_role", False)
    org = await make_org(db_session)
    t = await make_target(db_session, org, value=AWS_ACCT, kind=TargetKind.CLOUD_ACCOUNT, status=AttestationStatus.UNATTESTED)
    with pytest.raises(ForbiddenError):
        await attest_target(
            db_session, t.id, principal="tester", method=AttestationMethod.CLOUD_ROLE,
            checkbox_ack=True, evidence={"role_arn": ROLE_ARN}, cloud_verifier=_ok_verifier,
        )


# ---------------------------------------------------------------------------
# Gate integration — a cloud account is scannable only when attested + in scope
# ---------------------------------------------------------------------------
async def test_gate_allows_attested_cloud_account(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org, value=AWS_ACCT, kind=TargetKind.CLOUD_ACCOUNT, status=AttestationStatus.ATTESTED)
    eng = await make_engagement(
        db_session, org, in_scope=[{"kind": "CLOUD_ACCOUNT", "value": AWS_ACCT}],
    )
    decision = await check_scope(db_session, eng.id, AWS_ACCT)
    assert decision.allowed is True
    # enforce_scope must not raise for the attested, in-scope cloud target.
    await enforce_scope(db_session, eng.id, AWS_ACCT, actor="tester")


async def test_gate_denies_unattested_cloud_account(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org, value=AWS_ACCT, kind=TargetKind.CLOUD_ACCOUNT, status=AttestationStatus.UNATTESTED)
    eng = await make_engagement(
        db_session, org, in_scope=[{"kind": "CLOUD_ACCOUNT", "value": AWS_ACCT}],
    )
    decision = await check_scope(db_session, eng.id, AWS_ACCT)
    assert decision.allowed is False
    assert decision.code in ("target_not_attested", "attestation_expired")


def test_scope_normalization_and_coverage():
    nt = normalize_target("aws:123456789012")
    assert nt.kind == "CLOUD_ACCOUNT" and nt.value == "aws:123456789012"
    assert target_covers("CLOUD_ACCOUNT", "aws:123456789012", "aws:123456789012") is True
    assert target_covers("CLOUD_ACCOUNT", "aws:123456789012", "aws:999999999999") is False
    assert target_covers("CLOUD_ACCOUNT", "aws:*", "aws:123456789012") is True
    # a cloud rule never covers a non-cloud target, and vice-versa
    assert target_covers("CLOUD_ACCOUNT", "aws:123456789012", "example.com") is False
    assert target_covers("DOMAIN", "example.com", "aws:123456789012") is False
