"""Offline cloud runtime tests: real gate/SQLite rows, fake STS only."""

from __future__ import annotations

import json
import sys
import traceback
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.authz.errors import AuthorizationDenied, TargetNotAttested
from app.engine.credential_minter import CredentialMintError, mint_prowler_credentials
from app.models.audit import AuditAction, AuditEvent
from app.models.engagement import EngagementStatus
from app.models.target import AttestationMethod, AttestationStatus, TargetKind
from tests.conftest import make_engagement, make_org, make_target, utcnow

AWS_ACCOUNT = "aws:123456789012"
ROLE_ARN = "arn:aws:iam::123456789012:role/SecurityOpsScanner"
FAKE_CREDENTIALS = {
    "AccessKeyId": "fake-temporary-access-key",
    "SecretAccessKey": "fake-temporary-secret-key",
    "SessionToken": "fake-temporary-session-token",
}


async def cloud_context(session):
    org = await make_org(session)
    target = await make_target(
        session,
        org,
        value=AWS_ACCOUNT,
        kind=TargetKind.CLOUD_ACCOUNT,
        method=AttestationMethod.CLOUD_ROLE,
    )
    target.attestation_evidence = {
        "cloud_authorization": {"role_arn": ROLE_ARN, "verified": True},
        "region": "us-west-2",
    }
    engagement = await make_engagement(
        session, org, in_scope=[{"kind": "CLOUD_ACCOUNT", "value": AWS_ACCOUNT}]
    )
    await session.flush()
    return org, target, engagement


def no_sts(*args, **kwargs):
    pytest.fail("STS must not be called before authorization")


async def test_default_sts_uses_attested_role_external_id_and_15_minutes(
    db_session, monkeypatch
):
    org, target, engagement = await cloud_context(db_session)
    captured = {}

    def client(service, **kwargs):
        captured.update(service=service, **kwargs)
        return SimpleNamespace(assume_role=assume)

    def assume(**kwargs):
        captured.update(kwargs)
        return {"Credentials": dict(FAKE_CREDENTIALS)}

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=client))
    env = await mint_prowler_credentials(
        db_session, org_id=org.id, engagement_id=engagement.id, target_value=AWS_ACCOUNT
    )
    assert captured == {
        "service": "sts",
        "region_name": "us-west-2",
        "RoleArn": ROLE_ARN,
        "RoleSessionName": "security-ops-prowler",
        "ExternalId": f"security-ops-external-id={target.id}",
        "DurationSeconds": 900,
    }
    assert env["AWS_SESSION_TOKEN"] == FAKE_CREDENTIALS["SessionToken"]
    assert env["AWS_REGION"] == "us-west-2"
    audits = (await db_session.scalars(select(AuditEvent))).all()
    assert [a.action for a in audits] == [AuditAction.SCOPE_CHECK_ALLOWED]
    stored = json.dumps([target.attestation_evidence, [a.detail for a in audits]])
    for value in FAKE_CREDENTIALS.values():
        assert value not in stored


@pytest.mark.parametrize(
    "method", [AttestationMethod.OWNED, AttestationMethod.SELF_ATTESTED]
)
async def test_non_cloud_role_attestation_cannot_mint(db_session, method):
    org, target, engagement = await cloud_context(db_session)
    target.attestation_method = method
    await db_session.flush()
    with pytest.raises(CredentialMintError, match="CLOUD_ROLE"):
        await mint_prowler_credentials(
            db_session,
            org_id=org.id,
            engagement_id=engagement.id,
            target_value=AWS_ACCOUNT,
            assume_role=no_sts,
        )


@pytest.mark.parametrize(
    "denial",
    [
        "unattested",
        "expired",
        "revoked",
        "paused",
        "out_of_scope",
        "excluded",
        "expired_engagement",
        "stopped",
    ],
)
async def test_gate_denies_before_sts(db_session, denial):
    org, target, engagement = await cloud_context(db_session)
    if denial == "unattested":
        target.attestation_status = AttestationStatus.UNATTESTED
    elif denial == "expired":
        target.expires_at = utcnow() - timedelta(seconds=1)
    elif denial == "revoked":
        target.revoked_at = utcnow()
    elif denial == "paused":
        engagement.status = EngagementStatus.PAUSED
    elif denial == "out_of_scope":
        engagement.scope = {"in_scope": [], "exclusions": []}
    elif denial == "excluded":
        engagement.scope = {
            "in_scope": [{"kind": "CLOUD_ACCOUNT", "value": AWS_ACCOUNT}],
            "exclusions": [{"kind": "CLOUD_ACCOUNT", "value": AWS_ACCOUNT}],
        }
    elif denial == "expired_engagement":
        engagement.expires_at = utcnow() - timedelta(seconds=1)
    else:
        engagement.emergency_stopped = True
    await db_session.flush()
    error_type = TargetNotAttested if denial == "unattested" else AuthorizationDenied
    with pytest.raises(error_type):
        await mint_prowler_credentials(
            db_session,
            org_id=org.id,
            engagement_id=engagement.id,
            target_value=AWS_ACCOUNT,
            assume_role=no_sts,
        )
    audits = (await db_session.scalars(select(AuditEvent))).all()
    assert [a.action for a in audits] == [AuditAction.SCOPE_CHECK_DENIED]


@pytest.mark.parametrize("foreign", ["engagement", "target"])
async def test_tenant_scope_cannot_borrow_another_org_grant(db_session, foreign):
    org, target, engagement = await cloud_context(db_session)
    other = await make_org(db_session, slug="other")
    if foreign == "target":
        target.org_id = other.id
    else:
        engagement.org_id = other.id
    await db_session.flush()
    with pytest.raises((CredentialMintError, TargetNotAttested)):
        await mint_prowler_credentials(
            db_session,
            org_id=org.id,
            engagement_id=engagement.id,
            target_value=AWS_ACCOUNT,
            assume_role=no_sts,
        )


@pytest.mark.parametrize(
    "role",
    [
        "arn:aws:iam::999999999999:role/Other",
        "arn:aws:iam::123456789012:user/Scanner",
        None,
    ],
)
async def test_missing_or_mismatched_role_is_refused(db_session, role):
    org, target, engagement = await cloud_context(db_session)
    target.attestation_evidence = {"cloud_authorization": {"role_arn": role}}
    await db_session.flush()
    with pytest.raises(CredentialMintError, match="role ARN"):
        await mint_prowler_credentials(
            db_session,
            org_id=org.id,
            engagement_id=engagement.id,
            target_value=AWS_ACCOUNT,
            assume_role=no_sts,
        )


@pytest.mark.parametrize(
    "account", ["gcp:test-project", "azure:test-subscription", "aws:123", "example.com"]
)
async def test_unsupported_or_invalid_targets_do_not_request_credentials(
    db_session, account
):
    org, _, engagement = await cloud_context(db_session)
    with pytest.raises(CredentialMintError):
        await mint_prowler_credentials(
            db_session,
            org_id=org.id,
            engagement_id=engagement.id,
            target_value=account,
            assume_role=no_sts,
        )


@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        {"Credentials": {}},
        {"Credentials": {"AccessKeyId": "fake", "SecretAccessKey": "fake"}},
    ],
)
async def test_incomplete_sts_response_is_refused(db_session, response):
    org, _, engagement = await cloud_context(db_session)
    with pytest.raises(CredentialMintError, match="temporary credential fields"):
        await mint_prowler_credentials(
            db_session,
            org_id=org.id,
            engagement_id=engagement.id,
            target_value=AWS_ACCOUNT,
            assume_role=lambda *_: response,
        )


async def test_sts_exception_does_not_expose_credentials(db_session, caplog):
    org, _, engagement = await cloud_context(db_session)

    def broken_sts(*args):
        raise RuntimeError(json.dumps(FAKE_CREDENTIALS))

    with pytest.raises(CredentialMintError) as error:
        await mint_prowler_credentials(
            db_session,
            org_id=org.id,
            engagement_id=engagement.id,
            target_value=AWS_ACCOUNT,
            assume_role=broken_sts,
        )
    rendered = "".join(traceback.format_exception(error.value)) + caplog.text
    for value in FAKE_CREDENTIALS.values():
        assert value not in rendered
