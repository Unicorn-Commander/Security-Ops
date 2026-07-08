"""Operator finding-triage tests (spec §6) — set a finding's status, audited.

Pins the service invariants that make triage a safe, tamper-evident state change,
the counterpart to the Brigade hand-off:

* a real change flips the status AND appends exactly one ``FINDING_TRIAGED`` audit
  row (NEW -> VERIFIED, NEW -> FALSE_POSITIVE);
* setting ``HANDED_OFF`` via this path is refused (422) — that transition belongs
  to the hand-off flow;
* setting the current status is an idempotent no-op (no audit row);
* the MCP tool reuses the same service under org scoping — a cross-org finding is
  Not Found through ``_findings_set_status_impl``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from app.core.errors import NotFoundError, ValidationAppError
from app.mcp.server import _findings_set_status_impl
from app.models.audit import AuditAction, AuditEvent
from app.models.finding import Finding, FindingSeverity, FindingStatus
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
    # Load server-defaulted timestamps so FindingRead.model_validate has them
    # (mirrors the route/MCP path, which reads the row back via the repository).
    await session.refresh(finding)
    return finding


async def _triaged_rows(session) -> int:
    return int(
        await session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.action == AuditAction.FINDING_TRIAGED
            )
        )
        or 0
    )


async def test_new_to_verified_flips_and_audits(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng)

    result = await set_finding_status(
        db_session, finding=finding, new_status=FindingStatus.VERIFIED, actor="tester"
    )

    assert result.status == FindingStatus.VERIFIED
    assert await _triaged_rows(db_session) == 1

    row = (
        await db_session.execute(
            select(AuditEvent).where(AuditEvent.action == AuditAction.FINDING_TRIAGED)
        )
    ).scalars().one()
    assert row.decision == "triaged"
    assert row.org_id == org.id
    assert row.engagement_id == eng.id
    assert row.detail == {"from": "NEW", "to": "VERIFIED"}


async def test_new_to_false_positive_flips_and_audits(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng)

    result = await set_finding_status(
        db_session, finding=finding, new_status=FindingStatus.FALSE_POSITIVE, actor="tester"
    )

    assert result.status == FindingStatus.FALSE_POSITIVE
    assert await _triaged_rows(db_session) == 1


async def test_setting_handed_off_is_rejected(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng)

    with pytest.raises(ValidationAppError):
        await set_finding_status(
            db_session, finding=finding, new_status=FindingStatus.HANDED_OFF, actor="tester"
        )

    # Nothing changed and no audit row was written.
    await db_session.refresh(finding)
    assert finding.status == FindingStatus.NEW
    assert await _triaged_rows(db_session) == 0


async def test_same_status_is_idempotent_noop(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng, status=FindingStatus.VERIFIED)

    result = await set_finding_status(
        db_session, finding=finding, new_status=FindingStatus.VERIFIED, actor="tester"
    )

    assert result.status == FindingStatus.VERIFIED
    # No-op: no audit row.
    assert await _triaged_rows(db_session) == 0


async def test_reopen_closed_finding(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng, status=FindingStatus.FALSE_POSITIVE)

    result = await set_finding_status(
        db_session, finding=finding, new_status=FindingStatus.NEW, actor="tester"
    )

    assert result.status == FindingStatus.NEW
    assert await _triaged_rows(db_session) == 1


# ---------------------------------------------------------------------------
# MCP parity — same service, org-scoped; cross-org is Not Found.
# ---------------------------------------------------------------------------
def _ctx(session, org):
    from app.auth.sso import AuthUser, UserRole
    from app.mcp.auth import McpContext

    user = AuthUser(
        id="agent-1",
        email="demo@example.invalid",
        role=UserRole.OPERATOR,
        org_slug=org.slug,
        apps=["security-ops"],
    )
    return McpContext(session=session, org=org, user=user)


async def test_mcp_set_status_rejects_handed_off(db_session):
    # The MCP tool reaches the SAME service guard — HANDED_OFF is not settable here.
    org = await make_org(db_session, slug="pilot")
    eng = await make_engagement(db_session, org)
    finding = await _make_finding(db_session, org, eng)
    ctx = _ctx(db_session, org)

    with pytest.raises(ValidationAppError):
        await _findings_set_status_impl(ctx, finding.id, FindingStatus.HANDED_OFF)

    await db_session.refresh(finding)
    assert finding.status == FindingStatus.NEW
    assert await _triaged_rows(db_session) == 0


async def test_mcp_set_status_cross_org_not_found(db_session):
    org = await make_org(db_session, slug="pilot")
    other = await make_org(db_session, slug="other")
    eng = await make_engagement(db_session, other)
    finding = await _make_finding(db_session, other, eng)  # belongs to `other`
    ctx = _ctx(db_session, org)  # caller is `pilot`

    with pytest.raises(NotFoundError):
        await _findings_set_status_impl(ctx, finding.id, FindingStatus.VERIFIED)
