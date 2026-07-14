"""Compliance / SIEM surface tests.

These assert the new read-only GRC surfaces stay tenant-scoped and hash-chain
aware without relaxing the scan gate or the org boundary.
"""

from __future__ import annotations

from app.api.deps import get_current_org
from app.audit.writer import record_event
from app.auth.sso import AuthUser, UserRole
from app.models.audit import AuditAction
from app.repositories.audit import AuditRepository
from app.schemas.compliance import ComplianceOverviewRead
from tests.conftest import make_org


async def _seed_events(session, org_id, *, actor="system:test") -> None:
    await record_event(
        session,
        action=AuditAction.SCOPE_CHECK_ALLOWED,
        actor=actor,
        org_id=org_id,
        target="https://example.com",
        decision="allow",
        reason="in scope",
        detail={"framework": "SOC 2", "control": "CC7.2"},
    )
    await record_event(
        session,
        action=AuditAction.SCOPE_CHECK_DENIED,
        actor=actor,
        org_id=org_id,
        target="https://evil.example.net",
        decision="deny",
        reason="out of scope",
        detail={"framework": "HIPAA", "control": "164.312(b)"},
    )
    await record_event(
        session,
        action=AuditAction.FINDING_RECORDED,
        actor=actor,
        org_id=org_id,
        target="https://example.com/login",
        decision=None,
        reason="finding stored",
        detail={"severity": "HIGH"},
    )


async def test_audit_repository_builds_chain_and_posture_snapshot(db_session):
    org = await make_org(db_session, slug="pilot")
    other = await make_org(db_session, slug="other")
    await _seed_events(db_session, org.id)
    await record_event(
        db_session,
        action=AuditAction.SCOPE_CHECK_ALLOWED,
        actor="system:test",
        org_id=other.id,
        target="https://other.example.com",
        decision="allow",
    )

    snapshot = await AuditRepository(db_session).compliance_snapshot(org.id, window_days=30)
    assert snapshot["chain_verified"] is True
    assert snapshot["event_count"] == 3
    assert snapshot["by_action"]["SCOPE_CHECK_ALLOWED"] == 1
    assert snapshot["by_action"]["SCOPE_CHECK_DENIED"] == 1
    assert snapshot["posture"][0]["allowed_scans"] == 1
    assert snapshot["posture"][0]["denied_scans"] == 1
    assert snapshot["posture"][0]["findings_recorded"] == 1


async def test_compliance_overview_model_validates(db_session):
    org = await make_org(db_session, slug="pilot")
    await _seed_events(db_session, org.id)

    snapshot = await AuditRepository(db_session).compliance_snapshot(org.id)
    model = ComplianceOverviewRead.model_validate(
        {
            "audit": {
                "chain_head_hash": snapshot["chain_head_hash"],
                "chain_verified": snapshot["chain_verified"],
                "chain_break_index": snapshot["chain_break_index"],
                "event_count": snapshot["event_count"],
                "by_action": snapshot["by_action"],
            },
            "posture": snapshot["posture"],
            "controls": [
                {
                    "framework": "SOC 2",
                    "control": "CC7.2",
                    "title": "Detect and respond to unauthorized or out-of-scope activity",
                    "status": "evidence_ready",
                    "evidence": ["SCOPE_CHECK_DENIED"],
                }
            ],
        }
    )
    assert model.audit.chain_verified is True
    assert model.posture[0].denied_scans == 1


async def test_current_org_accepts_workspace_keycloak_group_fallback(db_session):
    org = await make_org(db_session, slug="pilot", keycloak_group="workspace-123")
    user = AuthUser(
        id="u-1",
        email="demo@example.invalid",
        role=UserRole.OPERATOR,
        org_slug="workspace-123",
        apps=["security-ops"],
    )

    resolved = await get_current_org(user, db_session)
    assert resolved.id == org.id
    assert resolved.keycloak_group == "workspace-123"
