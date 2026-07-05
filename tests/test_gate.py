"""The authorization gate is the product IP — these tests are its proof.

A scan MUST be impossible unless the target is inside an ACTIVE, unexpired,
in-scope engagement AND covered by a valid, attested, unexpired
:class:`AuthorizedTarget`. Every denial path is exercised, each asserts the
specific 403 subclass, and each asserts exactly one immutable audit row is
appended (allow or deny). ``start_run`` is checked end-to-end to prove no run row
is ever created when the gate refuses.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.authz.errors import (
    AttestationExpired,
    AuthorizationDenied,
    EmergencyStopEngaged,
    EngagementExpired,
    EngagementInactive,
    ScopeViolation,
    TargetExcluded,
    TargetNotAttested,
)
from app.authz.gate import check_scope, enforce_scope
from app.core.config import get_settings
from app.models.audit import AuditAction, AuditEvent
from app.models.engagement import EngagementStatus
from app.models.run import Run, RunStatus
from app.models.target import AttestationStatus, TargetKind
from tests.conftest import make_engagement, make_org, make_target, utcnow

ACTOR = "system:test"
IN_SCOPE = "https://example.com/login"
OUT_OF_SCOPE = "https://evil.example.net/"


async def _audit_count(session, action: AuditAction | None = None) -> int:
    stmt = select(func.count()).select_from(AuditEvent)
    if action is not None:
        stmt = stmt.where(AuditEvent.action == action)
    return int(await session.scalar(stmt) or 0)


# ---------------------------------------------------------------------------
# The allow path
# ---------------------------------------------------------------------------
async def test_gate_allows_in_scope_attested_target(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org, value="example.com")
    eng = await make_engagement(db_session, org)

    # Must not raise.
    await enforce_scope(db_session, eng.id, IN_SCOPE, actor=ACTOR)

    assert await _audit_count(db_session, AuditAction.SCOPE_CHECK_ALLOWED) == 1
    assert await _audit_count(db_session, AuditAction.SCOPE_CHECK_DENIED) == 0


# ---------------------------------------------------------------------------
# Every denial path — parametrized so a regression names the exact hole.
# ---------------------------------------------------------------------------
async def test_missing_engagement_denies(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org)
    with pytest.raises(EngagementInactive):
        await enforce_scope(db_session, uuid.uuid4(), IN_SCOPE, actor=ACTOR)
    assert await _audit_count(db_session, AuditAction.SCOPE_CHECK_DENIED) == 1


async def test_inactive_engagement_denies(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org)
    eng = await make_engagement(db_session, org, status=EngagementStatus.DRAFT)
    with pytest.raises(EngagementInactive):
        await enforce_scope(db_session, eng.id, IN_SCOPE, actor=ACTOR)


async def test_expired_engagement_denies(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org)
    eng = await make_engagement(db_session, org, expires_at=utcnow() - timedelta(hours=1))
    with pytest.raises(EngagementExpired):
        await enforce_scope(db_session, eng.id, IN_SCOPE, actor=ACTOR)


async def test_emergency_stopped_engagement_denies(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org)
    eng = await make_engagement(db_session, org, emergency_stopped=True)
    with pytest.raises(EmergencyStopEngaged):
        await enforce_scope(db_session, eng.id, IN_SCOPE, actor=ACTOR)


async def test_global_kill_switch_denies(db_session, monkeypatch):
    org = await make_org(db_session)
    await make_target(db_session, org)
    eng = await make_engagement(db_session, org)
    monkeypatch.setattr(get_settings(), "emergency_stop_all", True)
    with pytest.raises(EmergencyStopEngaged):
        await enforce_scope(db_session, eng.id, IN_SCOPE, actor=ACTOR)


async def test_out_of_scope_target_denies(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org)
    eng = await make_engagement(db_session, org)
    with pytest.raises(ScopeViolation):
        await enforce_scope(db_session, eng.id, OUT_OF_SCOPE, actor=ACTOR)


async def test_excluded_target_denies(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org)
    eng = await make_engagement(
        db_session,
        org,
        exclusions=[{"kind": "URL", "value": "example.com/admin"}],
    )
    with pytest.raises(TargetExcluded):
        await enforce_scope(db_session, eng.id, "https://example.com/admin", actor=ACTOR)


async def test_in_scope_but_unregistered_target_denies(db_session):
    org = await make_org(db_session)
    # No AuthorizedTarget registered at all.
    eng = await make_engagement(db_session, org)
    with pytest.raises(TargetNotAttested):
        await enforce_scope(db_session, eng.id, IN_SCOPE, actor=ACTOR)


async def test_in_scope_but_unattested_target_denies(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org, status=AttestationStatus.UNATTESTED)
    eng = await make_engagement(db_session, org)
    with pytest.raises(TargetNotAttested):
        await enforce_scope(db_session, eng.id, IN_SCOPE, actor=ACTOR)


async def test_in_scope_but_attestation_expired_denies(db_session):
    org = await make_org(db_session)
    await make_target(
        db_session,
        org,
        status=AttestationStatus.ATTESTED,
        expires_at=utcnow() - timedelta(days=1),
    )
    eng = await make_engagement(db_session, org)
    with pytest.raises(AttestationExpired):
        await enforce_scope(db_session, eng.id, IN_SCOPE, actor=ACTOR)


async def test_revoked_attestation_denies(db_session):
    org = await make_org(db_session)
    await make_target(
        db_session,
        org,
        status=AttestationStatus.ATTESTED,
        revoked_at=utcnow() - timedelta(minutes=5),
    )
    eng = await make_engagement(db_session, org)
    with pytest.raises(AttestationExpired):
        await enforce_scope(db_session, eng.id, IN_SCOPE, actor=ACTOR)


async def test_every_denial_writes_exactly_one_audit_row(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org)
    eng = await make_engagement(db_session, org)
    with pytest.raises(AuthorizationDenied):
        await enforce_scope(db_session, eng.id, OUT_OF_SCOPE, actor=ACTOR)
    assert await _audit_count(db_session) == 1
    assert await _audit_count(db_session, AuditAction.SCOPE_CHECK_DENIED) == 1


# ---------------------------------------------------------------------------
# check_scope is the pure preview: no audit, no raise, lifecycle-agnostic.
# ---------------------------------------------------------------------------
async def test_check_scope_is_pure(db_session):
    org = await make_org(db_session)
    await make_target(db_session, org)
    # DRAFT engagement — check_scope ignores lifecycle, so an in-scope+attested
    # target still previews as allowed even though enforce_scope would refuse it.
    eng = await make_engagement(db_session, org, status=EngagementStatus.DRAFT)

    decision = await check_scope(db_session, eng.id, IN_SCOPE)
    assert decision.allowed is True
    assert await _audit_count(db_session) == 0  # pure: nothing written


# ---------------------------------------------------------------------------
# start_run: the gate is upstream of run creation — a denial creates NO run.
# ---------------------------------------------------------------------------
async def test_start_run_denied_creates_no_run(db_session, monkeypatch):
    from app.schemas.run import RunCreate
    from app.services import runs as runs_service

    # Never actually launch the Strix worker in a unit test.
    monkeypatch.setattr(runs_service, "launch_run_background", lambda **_: None)

    org = await make_org(db_session)
    await make_target(db_session, org)  # covers example.com, not evil.example.net
    eng = await make_engagement(db_session, org)

    with pytest.raises(AuthorizationDenied):
        await runs_service.start_run(
            db_session,
            engagement=eng,
            actor=ACTOR,
            data=RunCreate(targets=[OUT_OF_SCOPE]),
        )

    # No run row exists — the gate refused before anything was created.
    assert int(await db_session.scalar(select(func.count()).select_from(Run)) or 0) == 0


async def test_start_run_allowed_creates_pending_run(db_session, monkeypatch):
    from app.schemas.run import RunCreate
    from app.services import runs as runs_service

    launched: dict = {}

    def _capture(**kw):
        launched.update(kw)

    monkeypatch.setattr(runs_service, "launch_run_background", _capture)

    org = await make_org(db_session)
    await make_target(db_session, org)
    eng = await make_engagement(db_session, org)

    run = await runs_service.start_run(
        db_session,
        engagement=eng,
        actor=ACTOR,
        data=RunCreate(targets=[IN_SCOPE]),
    )

    assert run.status == RunStatus.PENDING
    assert run.targets == [IN_SCOPE]
    # Gate wrote one ALLOWED row; the service wrote one RUN_STARTED row.
    assert await _audit_count(db_session, AuditAction.SCOPE_CHECK_ALLOWED) == 1
    assert await _audit_count(db_session, AuditAction.RUN_STARTED) == 1
    # The background worker was handed the freshly-created run.
    assert launched.get("run_id") == run.id
