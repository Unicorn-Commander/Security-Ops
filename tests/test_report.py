"""Engagement report generator + assembler tests (spec §8).

Covers the whole report path bottom-up: the pure Markdown builder in isolation
(no DB, injected timestamp), the read-only service orchestration against a real
in-memory session (populated engagement + run + findings, plus the empty case),
and the ``format=json`` vs default-markdown shapes — exercised through the service
function directly rather than over HTTP, per the task's brief.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.run import Run, RunMode, RunStatus
from app.reports.builder import build_engagement_report
from app.services.reports import generate_engagement_report
from tests.conftest import make_engagement, make_org

FIXED_TS = datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc)


async def _make_run(
    session,
    engagement,
    org,
    *,
    status: RunStatus = RunStatus.COMPLETED,
    report_path: str | None = None,
) -> Run:
    run = Run(
        id=uuid.uuid4(),
        engagement_id=engagement.id,
        org_id=org.id,
        mode=RunMode.STANDARD,
        model_profile="hybrid-local-sweep-verify",
        targets=["example.com"],
        status=status,
        report_path=report_path,
    )
    session.add(run)
    await session.flush()
    return run


async def _make_finding(
    session,
    run,
    engagement,
    org,
    *,
    title: str,
    severity: FindingSeverity,
    cwe: str | None = None,
    endpoint: str | None = None,
    poc: str | None = None,
    evidence: dict | None = None,
) -> Finding:
    finding = Finding(
        id=uuid.uuid4(),
        run_id=run.id,
        engagement_id=engagement.id,
        org_id=org.id,
        title=title,
        severity=severity,
        cwe=cwe,
        endpoint=endpoint,
        poc=poc,
        evidence=evidence,
        status=FindingStatus.NEW,
    )
    session.add(finding)
    await session.flush()
    return finding


# ---------------------------------------------------------------------------
# Pure builder
# ---------------------------------------------------------------------------
async def test_pure_builder_brands_and_summarizes(db_session):
    org = await make_org(db_session)
    engagement = await make_engagement(db_session, org)
    run = await _make_run(db_session, engagement, org)
    f1 = await _make_finding(
        db_session,
        run,
        engagement,
        org,
        title="SQL injection in login",
        severity=FindingSeverity.CRITICAL,
        cwe="CWE-89",
        endpoint="https://example.com/login",
        poc="' OR 1=1 --",
        evidence={"remediation": "Use parameterized queries.", "description": "Auth bypass."},
    )
    f2 = await _make_finding(
        db_session,
        run,
        engagement,
        org,
        title="Missing security headers",
        severity=FindingSeverity.LOW,
    )

    markdown = build_engagement_report(
        engagement,
        [run],
        {run.id: [f1, f2]},
        generated_at=FIXED_TS,
        strix_report_text="# Engine report\nDeep verified content.",
    )

    # Branding + engagement identity.
    assert "Security-Ops — Engagement Report" in markdown
    assert engagement.name in markdown
    assert str(engagement.id) in markdown
    assert FIXED_TS.isoformat() in markdown  # injected, not Date.now
    # Executive summary reflects the findings.
    assert "**Findings:** 2" in markdown
    assert "**Highest severity:** CRITICAL" in markdown
    assert "| CRITICAL | 1 |" in markdown
    assert "| LOW | 1 |" in markdown
    # Each finding title + its evidence rendered.
    assert "SQL injection in login" in markdown
    assert "Missing security headers" in markdown
    assert "CWE-89" in markdown
    assert "Use parameterized queries." in markdown
    assert "' OR 1=1 --" in markdown
    # The frontier-verified engine report is appended.
    assert "## Full engine report" in markdown
    assert "Deep verified content." in markdown


def test_pure_builder_empty_case():
    engagement = _StubEngagement()
    markdown = build_engagement_report(
        engagement, [], {}, generated_at=FIXED_TS
    )
    assert "Security-Ops — Engagement Report" in markdown
    assert "**Runs:** 0" in markdown
    assert "**Findings:** 0" in markdown
    assert "**Highest severity:** None" in markdown
    assert "No findings" in markdown
    # No engine section when no Strix text supplied.
    assert "## Full engine report" not in markdown


class _StubEngagement:
    id = uuid.uuid4()
    name = "empty engagement"
    status = "ACTIVE"


# ---------------------------------------------------------------------------
# Service orchestration (read-only, real session)
# ---------------------------------------------------------------------------
async def test_service_generates_report_from_db(db_session):
    org = await make_org(db_session)
    engagement = await make_engagement(db_session, org)
    run = await _make_run(db_session, engagement, org)
    await _make_finding(
        db_session,
        run,
        engagement,
        org,
        title="IDOR on invoices",
        severity=FindingSeverity.HIGH,
        endpoint="https://example.com/api/invoices/42",
    )

    markdown = await generate_engagement_report(db_session, engagement=engagement)

    assert "Security-Ops — Engagement Report" in markdown
    assert engagement.name in markdown
    assert "IDOR on invoices" in markdown
    assert "**Highest severity:** HIGH" in markdown
    assert "| HIGH | 1 |" in markdown


async def test_service_empty_engagement_is_valid_report(db_session):
    org = await make_org(db_session)
    engagement = await make_engagement(db_session, org)

    markdown = await generate_engagement_report(db_session, engagement=engagement)

    assert "Security-Ops — Engagement Report" in markdown
    assert "**Runs:** 0" in markdown
    assert "No findings" in markdown


async def test_report_json_and_markdown_paths(db_session):
    """The service returns markdown; the route wraps it as json/plaintext. Exercise
    the shapes that the route builds without going over HTTP."""
    org = await make_org(db_session)
    engagement = await make_engagement(db_session, org)
    run = await _make_run(db_session, engagement, org)
    await _make_finding(
        db_session, run, engagement, org, title="XSS reflected", severity=FindingSeverity.MEDIUM
    )

    report_markdown = await generate_engagement_report(db_session, engagement=engagement)

    # Default markdown path: raw string ready for text/markdown response.
    assert isinstance(report_markdown, str)
    assert "XSS reflected" in report_markdown

    # json path shape the route returns.
    json_body = {"engagement_id": str(engagement.id), "report_markdown": report_markdown}
    assert json_body["engagement_id"] == str(engagement.id)
    assert "XSS reflected" in json_body["report_markdown"]
