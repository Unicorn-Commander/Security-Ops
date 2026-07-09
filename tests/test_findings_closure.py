"""Closed finding metadata is recorded and surfaced."""

from __future__ import annotations

import uuid

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.schemas.finding import FindingRead
from app.services.findings import set_finding_status
from tests.conftest import make_engagement, make_org


async def _make_finding(session, org, engagement, *, status=FindingStatus.NEW) -> Finding:
    finding = Finding(
        id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        engagement_id=engagement.id,
        org_id=org.id,
        title="Reflected XSS in /search",
        severity=FindingSeverity.MEDIUM,
        cwe="CWE-79",
        endpoint="https://example.com/search",
        status=status,
    )
    session.add(finding)
    await session.flush()
    await session.refresh(finding)
    return finding


async def test_terminal_closure_fields_are_written_and_readable(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng)

    updated = await set_finding_status(
        db_session,
        finding=finding,
        new_status=FindingStatus.FALSE_POSITIVE,
        actor="demo@example.invalid",
        closure_reason="Verified in staging only",
    )

    assert updated.status == FindingStatus.FALSE_POSITIVE
    assert updated.closure_reason == "Verified in staging only"
    assert updated.closed_by == "demo@example.invalid"
    assert updated.closed_at is not None

    read = FindingRead.model_validate(updated)
    assert read.closure_reason == "Verified in staging only"
    assert read.closed_by == "demo@example.invalid"
    assert read.closed_at is not None


async def test_reopening_clears_closure_metadata(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng, status=FindingStatus.REMEDIATED)
    finding.closure_reason = "Fixed upstream"
    finding.closed_by = "demo@example.invalid"
    await db_session.flush()

    reopened = await set_finding_status(
        db_session,
        finding=finding,
        new_status=FindingStatus.NEW,
        actor="demo@example.invalid",
    )

    assert reopened.status == FindingStatus.NEW
    assert reopened.closure_reason is None
    assert reopened.closed_by is None
    assert reopened.closed_at is None
