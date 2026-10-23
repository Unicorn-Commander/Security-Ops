"""Exercise the gated Prowler pipeline with fake STS and a local fake executable."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.authz.errors import TargetNotAttested
from app.core.config import get_settings
from app.engine import credential_minter, prowler_runner, strix_runner
from app.engine.cloud_credentials import isolated_prowler_env, scrub_cloud_output
from app.engine.credential_minter import CredentialMintError
from app.engine.prowler_runner import ProwlerRunner
from app.models.audit import AuditAction, AuditEvent
from app.models.engagement import EngagementStatus
from app.models.finding import Finding
from app.models.run import Run, RunStatus
from app.models.target import AttestationStatus
from app.schemas.run import RunCreate
from app.services.reports import generate_engagement_report
from app.services.runs import start_run
from tests.test_cloud_credentials import AWS_ACCOUNT, FAKE_CREDENTIALS, cloud_context


@pytest.fixture
def offline_runtime(monkeypatch, tmp_path):
    calls = {"sts": [], "spawns": [], "events": []}

    def assume_role(**kwargs):
        calls["sts"].append(kwargs)
        return {"Credentials": dict(FAKE_CREDENTIALS)}

    monkeypatch.setitem(
        sys.modules,
        "boto3",
        SimpleNamespace(
            client=lambda *a, **kw: SimpleNamespace(assume_role=assume_role)
        ),
    )
    monkeypatch.setattr(get_settings(), "run_dispatch_mode", "queue")
    monkeypatch.setattr(get_settings(), "strix_verify_pass", False)

    async def emit(**kwargs):
        calls["events"].append(kwargs)

    monkeypatch.setattr("app.services.run_events.emit_run_event", emit)
    original_spawn = asyncio.create_subprocess_exec

    async def spawn(*args, **kwargs):
        proc = await original_spawn(*args, **kwargs)
        calls["spawns"].append((args, dict(kwargs["env"]), proc))
        return proc

    monkeypatch.setattr(strix_runner.asyncio, "create_subprocess_exec", spawn)
    # This is a local Python program, not Prowler. It never imports a cloud SDK
    # or opens a network connection, but uses the real subprocess/parse/store path.
    script = tmp_path / "fake_prowler.py"
    script.write_text("""
import json
import os
from pathlib import Path
import sys
import time

out = Path(sys.argv[sys.argv.index("--output-directory") + 1])
key = os.environ["AWS_ACCESS_KEY_ID"]
secret = os.environ["AWS_SECRET_ACCESS_KEY"]
token = os.environ["AWS_SESSION_TOKEN"]
print(secret, flush=True)
print(token, file=sys.stderr, flush=True)
finding = {
    "status_code": "FAIL", "severity": "High",
    "finding_info": {"title": "exposed " + key, "desc": secret},
    "status_detail": token,
    "metadata": {"event_code": "fake-check", secret: [token]},
    "resources": [{"uid": "resource/" + token}],
    "remediation": {"desc": secret},
    "Credentials": {"SecretAccessKey": "unrelated-fake-secret"},
}
(out / "prowler.ocsf.json").write_text(json.dumps([finding]))
if "--hang" in sys.argv:
    time.sleep(30)
sys.exit(3)
""")
    original_prepare = ProwlerRunner.prepare

    def prepare(self, **kwargs):
        invocation = original_prepare(self, **kwargs)
        invocation.command = [sys.executable, str(script), *invocation.command[1:]]
        if calls.get("hang"):
            invocation.command.append("--hang")
        calls["invocation"] = invocation
        return invocation

    monkeypatch.setattr(ProwlerRunner, "prepare", prepare)
    calls["config"] = get_settings().model_copy(
        update={
            "runs_dir": str(tmp_path / "runs"),
            "runner_stop_poll_seconds": 0,
        }
    )
    return calls


async def queued_cloud_run(session):
    org, target, engagement = await cloud_context(session)
    run = await start_run(
        session,
        engagement=engagement,
        actor="system:test",
        data=RunCreate(engine="prowler", targets=[AWS_ACCOUNT]),
    )
    return org, target, engagement, run


def assert_runtime_cleared(runner, calls):
    assert runner._credential_env == {}
    assert runner._active_run_id is None
    assert runner._output_dir is None
    if "invocation" in calls:
        invocation = calls["invocation"]
        assert invocation.env == {}
        assert not list(invocation.run_dir.glob(".prowler-*"))
        assert not invocation.pid_path.exists()


async def test_fake_sts_and_subprocess_complete_through_gate_without_leaking(
    db_session, offline_runtime, monkeypatch, caplog
):
    caplog.set_level(logging.INFO)
    calls = offline_runtime
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "SECOPS_DATABASE_URL",
        "SECOPS_INTERNAL_LITELLM_API_KEY",
    ):
        monkeypatch.setenv(name, "fake-host-credential")
    org, target, engagement, run = await queued_cloud_run(db_session)
    runner = ProwlerRunner(db_session, config=calls["config"])
    result = await runner.execute(run=run, engagement=engagement)
    assert result.status == RunStatus.COMPLETED
    assert len(calls["sts"]) == len(calls["spawns"]) == 1
    command, env, proc = calls["spawns"][0]
    assert proc.returncode == 3
    assert env["AWS_ACCESS_KEY_ID"] == FAKE_CREDENTIALS["AccessKeyId"]
    assert "fake-host-credential" not in env.values()
    assert env["AWS_CONFIG_FILE"] == env["AWS_SHARED_CREDENTIALS_FILE"] == os.devnull
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert ".prowler-" in env["HOME"]
    assert "AWS_CONTAINER_CREDENTIALS_FULL_URI" not in env
    assert "AWS_PROFILE" not in env
    assert "AWS_WEB_IDENTITY_TOKEN_FILE" not in env
    assert "AZURE_CLIENT_SECRET" not in env
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in env
    assert "SECOPS_DATABASE_URL" not in env
    assert "SECOPS_INTERNAL_LITELLM_API_KEY" not in env
    findings = (await db_session.scalars(select(Finding))).all()
    assert len(findings) == 1
    assert findings[0].title == "exposed [REDACTED]"
    assert findings[0].org_id == org.id
    assert findings[0].evidence["raw"]["Credentials"] == "[REDACTED]"
    audits = (await db_session.scalars(select(AuditEvent))).all()
    assert sum(a.action == AuditAction.SCOPE_CHECK_ALLOWED for a in audits) == 3
    report = await generate_engagement_report(db_session, engagement=engagement)
    assert "exposed [REDACTED]" in report
    assert calls["invocation"].log_path.read_text() == ""
    persisted = (
        json.dumps(
            [
                [f.evidence for f in findings],
                [a.detail for a in audits],
                target.attestation_evidence,
                calls["events"],
                command,
            ],
            default=str,
        )
        + report
        + caplog.text
    )
    for secret in (*FAKE_CREDENTIALS.values(), "unrelated-fake-secret"):
        assert secret not in persisted
    assert_runtime_cleared(runner, calls)


async def test_start_gate_refuses_unattested_cloud_target(db_session, offline_runtime):
    _, target, engagement = await cloud_context(db_session)
    target.attestation_status = AttestationStatus.UNATTESTED
    await db_session.flush()
    with pytest.raises(TargetNotAttested):
        await start_run(
            db_session,
            engagement=engagement,
            actor="system:test",
            data=RunCreate(engine="prowler", targets=[AWS_ACCOUNT]),
        )
    assert not (await db_session.scalars(select(Run))).all()
    assert offline_runtime["sts"] == offline_runtime["spawns"] == []
    audit = (await db_session.scalars(select(AuditEvent))).one()
    assert audit.action == AuditAction.SCOPE_CHECK_DENIED


@pytest.mark.parametrize("denial", ["unattested", "paused"])
async def test_queued_run_rechecks_authorization_before_sts(
    db_session, offline_runtime, denial
):
    _, target, engagement, run = await queued_cloud_run(db_session)
    if denial == "unattested":
        target.attestation_status = AttestationStatus.UNATTESTED
    else:
        engagement.status = EngagementStatus.PAUSED
    await db_session.commit()
    runner = ProwlerRunner(db_session, config=offline_runtime["config"])
    result = await runner.execute(run=run, engagement=engagement)
    assert result.status == RunStatus.DENIED
    assert offline_runtime["sts"] == offline_runtime["spawns"] == []
    assert_runtime_cleared(runner, offline_runtime)


@pytest.mark.parametrize(
    "targets",
    [
        [],
        [AWS_ACCOUNT, "aws:999999999999"],
        ["gcp:test-project"],
        ["azure:test-subscription"],
        ["not-a-cloud-account"],
    ],
)
async def test_unsupported_run_never_spawns_or_uses_ambient_credentials(
    db_session, offline_runtime, targets
):
    _, _, engagement, run = await queued_cloud_run(db_session)
    run.targets = targets
    await db_session.commit()
    runner = ProwlerRunner(db_session, config=offline_runtime["config"])
    result = await runner.execute(run=run, engagement=engagement)
    assert result.status == RunStatus.FAILED
    assert offline_runtime["sts"] == offline_runtime["spawns"] == []
    assert_runtime_cleared(runner, offline_runtime)


@pytest.mark.parametrize("change", ["revoke", "retarget"])
async def test_change_during_sts_is_denied_before_spawn(
    db_session, offline_runtime, monkeypatch, change
):
    _, target, engagement, run = await queued_cloud_run(db_session)
    original_mint = credential_minter.mint_prowler_credentials

    async def mint_then_change(*args, **kwargs):
        env = await original_mint(*args, **kwargs)
        if change == "revoke":
            target.attestation_status = AttestationStatus.REVOKED
        else:
            run.targets = ["aws:999999999999"]
        await db_session.commit()
        return env

    monkeypatch.setattr(prowler_runner, "mint_prowler_credentials", mint_then_change)
    runner = ProwlerRunner(db_session, config=offline_runtime["config"])
    result = await runner.execute(run=run, engagement=engagement)
    assert result.status in (RunStatus.DENIED, RunStatus.FAILED)
    assert len(offline_runtime["sts"]) == 1
    assert offline_runtime["spawns"] == []
    assert_runtime_cleared(runner, offline_runtime)


async def test_runner_failure_does_not_log_sts_secrets(
    db_session, offline_runtime, monkeypatch, caplog
):
    _, _, engagement, run = await queued_cloud_run(db_session)

    def fail(*args, **kwargs):
        raise RuntimeError(json.dumps(FAKE_CREDENTIALS))

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=fail))
    runner = ProwlerRunner(db_session, config=offline_runtime["config"])
    result = await runner.execute(run=run, engagement=engagement)
    assert result.status == RunStatus.FAILED
    assert result.error == "STS AssumeRole failed"
    for secret in FAKE_CREDENTIALS.values():
        assert secret not in caplog.text + result.error + json.dumps(
            offline_runtime["events"], default=str
        )
    assert offline_runtime["spawns"] == []
    assert_runtime_cleared(runner, offline_runtime)


async def test_timeout_cleans_up_credentials_and_private_output(
    db_session, offline_runtime
):
    _, _, engagement, run = await queued_cloud_run(db_session)
    offline_runtime["hang"] = True
    runner = ProwlerRunner(db_session, config=offline_runtime["config"])
    result = await runner.execute(run=run, engagement=engagement, timeout=0.1)
    assert result.status == RunStatus.STOPPED
    assert offline_runtime["spawns"][0][2].returncode is not None
    assert_runtime_cleared(runner, offline_runtime)


async def test_cancellation_terminates_child_and_clears_credentials(
    db_session, offline_runtime, monkeypatch
):
    _, _, engagement, run = await queued_cloud_run(db_session)
    offline_runtime["hang"] = True
    spawned = asyncio.Event()
    original_spawn = asyncio.create_subprocess_exec

    async def spawn(*args, **kwargs):
        proc = await original_spawn(*args, **kwargs)
        spawned.set()
        return proc

    monkeypatch.setattr(strix_runner.asyncio, "create_subprocess_exec", spawn)
    runner = ProwlerRunner(db_session, config=offline_runtime["config"])
    task = asyncio.create_task(runner.execute(run=run, engagement=engagement))
    try:
        await asyncio.wait_for(spawned.wait(), timeout=3)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert offline_runtime["spawns"][0][2].returncode is not None
    assert_runtime_cleared(runner, offline_runtime)


async def test_reused_runner_cannot_reuse_credentials_from_an_earlier_run(
    db_session, offline_runtime
):
    _, target, engagement, run = await queued_cloud_run(db_session)
    runner = ProwlerRunner(db_session, config=offline_runtime["config"])
    assert (
        await runner.execute(run=run, engagement=engagement)
    ).status == RunStatus.COMPLETED
    second = await start_run(
        db_session,
        engagement=engagement,
        actor="system:test",
        data=RunCreate(engine="prowler", targets=[AWS_ACCOUNT]),
    )
    target.attestation_status = AttestationStatus.REVOKED
    await db_session.commit()
    assert (
        await runner.execute(run=second, engagement=engagement)
    ).status == RunStatus.DENIED
    assert len(offline_runtime["sts"]) == len(offline_runtime["spawns"]) == 1
    assert_runtime_cleared(runner, offline_runtime)


def test_prepare_cannot_fall_back_to_host_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake-host-key")
    runner = ProwlerRunner(None)
    with pytest.raises(CredentialMintError, match="requires this run's credentials"):
        runner.prepare(run=SimpleNamespace(id="unminted"), engagement=object())


def test_scrub_nested_fields_values_and_url_encoded_echoes():
    value = {
        "description": "fake/token+= and fake%2Ftoken%2B%3D",
        "nested": [{"aws_secret_access_key": "different-fake-value"}],
        "fake/token+=": "safe",
        "public_resource": "arn:aws:s3:::example",
    }
    clean = scrub_cloud_output(value, ["fake/token+="])
    assert clean == {
        "description": "[REDACTED] and [REDACTED]",
        "nested": [{"aws_secret_access_key": "[REDACTED]"}],
        "[REDACTED]": "safe",
        "public_resource": "arn:aws:s3:::example",
    }


def test_environment_cannot_inherit_credential_providers(tmp_path):
    credentials = {
        "AWS_ACCESS_KEY_ID": "fake-key",
        "AWS_SECRET_ACCESS_KEY": "fake-secret",
        "AWS_SESSION_TOKEN": "fake-token",
        "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-east-1",
    }
    ambient = {
        "PATH": "/fake/bin",
        "LANG": "C.UTF-8",
        "HOME": "/fake/host-home",
        "AWS_SECURITY_TOKEN": "host",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN": "host",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "host",
        "AWS_ROLE_ARN": "host",
        "BOTO_CONFIG": "host",
        "AZURE_TENANT_ID": "host",
        "GCLOUD_PROJECT": "host",
        "PYTHONPATH": "/fake/host-code",
        "LD_PRELOAD": "/fake/host-code",
    }
    env = isolated_prowler_env(credentials, home=tmp_path, ambient=ambient)
    assert env["PATH"] == "/fake/bin"
    assert env["HOME"] == str(tmp_path)
    assert "host" not in env.values()
    assert "PYTHONPATH" not in env and "LD_PRELOAD" not in env
    assert credentials["AWS_ACCESS_KEY_ID"] == "fake-key"
    assert ambient["HOME"] == "/fake/host-home"
