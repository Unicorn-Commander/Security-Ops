"""Brigade hand-off orchestration (spec §8) — "Security-Ops finds; Brigade fixes."

Pins the honest stub boundary (no Brigade endpoint => 501, not a silent success),
the happy path (finding flips to HANDED_OFF with a ref + a FINDING_HANDOFF audit
row), and the guards (already handed off => 409; false positive => 422).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from app.engine.brigade_handoff import (
    BrigadeHandoffClient,
    HandoffNotConfigured,
    handoff_finding,
)
from app.core.errors import ConflictError, ValidationAppError
from app.models.audit import AuditAction, AuditEvent
from app.models.finding import Finding, FindingSeverity, FindingStatus
from tests.conftest import make_engagement, make_org, make_target


async def _make_finding(session, org, engagement, *, status=FindingStatus.NEW) -> Finding:
    finding = Finding(
        id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        engagement_id=engagement.id,
        org_id=org.id,
        title="SQL injection in /login",
        severity=FindingSeverity.HIGH,
        cwe="CWE-89",
        endpoint="https://example.com/login",
        poc="' OR 1=1 --",
        evidence={"remediation": "Use parameterized queries."},
        status=status,
    )
    session.add(finding)
    await session.flush()
    return finding


class _StubClient:
    """A configured Brigade client that records the submitted payload."""

    agent = "security-remediation"

    def __init__(self, response=None):
        self.response = response or {"id": "BRIG-123"}
        self.submitted = None

    async def submit(self, payload):
        self.submitted = payload
        return self.response


async def test_handoff_unconfigured_surfaces_501(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng)

    # An unconfigured real client (no base_url) is the honest Phase-2 boundary.
    with pytest.raises(HandoffNotConfigured):
        await handoff_finding(
            db_session, finding=finding, actor="tester", client=BrigadeHandoffClient()
        )
    # The finding was NOT flipped — nothing was actually handed off.
    await db_session.refresh(finding)
    assert finding.status == FindingStatus.NEW


async def test_handoff_success_flips_status_and_audits(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng)

    client = _StubClient({"ticket_id": "BRIG-777"})
    result = await handoff_finding(
        db_session, finding=finding, actor="tester", engagement=eng, client=client
    )

    assert result.status == FindingStatus.HANDED_OFF
    assert result.handoff_ref == "BRIG-777"
    # Payload carried the finding's evidence for Brigade to act on without re-scanning.
    assert client.submitted.finding_id == str(finding.id)

    audit_rows = int(
        await db_session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.action == AuditAction.FINDING_HANDOFF
            )
        )
        or 0
    )
    assert audit_rows == 1


async def test_handoff_twice_conflicts(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng, status=FindingStatus.HANDED_OFF)

    with pytest.raises(ConflictError):
        await handoff_finding(db_session, finding=finding, actor="tester", client=_StubClient())


async def test_handoff_false_positive_rejected(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng, status=FindingStatus.FALSE_POSITIVE)

    with pytest.raises(ValidationAppError):
        await handoff_finding(db_session, finding=finding, actor="tester", client=_StubClient())
