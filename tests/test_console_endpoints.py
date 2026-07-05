"""Console read-only endpoint tests (spec §6) — the org-scoped list + overview
surfaces the new console needs.

Exercised through the repository / overview layer directly against a real
in-memory session (no HTTP, so no auth wiring), per the suite convention in
``test_report.py``. The load-bearing guarantees under test:

* ``RunRepository.list_for_org`` / ``FindingRepository.list_for_org`` return ONLY
  the caller-org's rows (tenant isolation) and honor their status/severity
  filters, newest first;
* ``OverviewRepository`` computes correct ``by_status`` / ``by_severity`` /
  ``active`` / ``attested`` / ``running`` / ``open`` counts, all org-scoped.
"""

from __future__ import annotations

import uuid

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.run import Run, RunMode, RunStatus
from app.models.target import AttestationStatus, TargetKind
from app.repositories.findings import FindingRepository
from app.repositories.overview import OverviewRepository
from app.repositories.runs import RunRepository
from app.schemas.overview import OverviewRead
from tests.conftest import make_engagement, make_org, make_target


async def _make_run(
    session,
    engagement,
    org,
    *,
    status: RunStatus = RunStatus.PENDING,
) -> Run:
    run = Run(
        id=uuid.uuid4(),
        engagement_id=engagement.id,
        org_id=org.id,
        mode=RunMode.STANDARD,
        model_profile="hybrid-local-sweep-verify",
        targets=["example.com"],
        status=status,
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
    title: str = "finding",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    status: FindingStatus = FindingStatus.NEW,
) -> Finding:
    finding = Finding(
        id=uuid.uuid4(),
        run_id=run.id,
        engagement_id=engagement.id,
        org_id=org.id,
        title=title,
        severity=severity,
        status=status,
    )
    session.add(finding)
    await session.flush()
    return finding


# ---------------------------------------------------------------------------
# RunRepository.list_for_org
# ---------------------------------------------------------------------------
async def test_runs_list_for_org_isolates_and_filters(db_session):
    org = await make_org(db_session, slug="alpha")
    other = await make_org(db_session, slug="beta")
    eng = await make_engagement(db_session, org)
    other_eng = await make_engagement(db_session, other)

    r_pending = await _make_run(db_session, eng, org, status=RunStatus.PENDING)
    r_running = await _make_run(db_session, eng, org, status=RunStatus.RUNNING)
    # Cross-org run must never surface.
    await _make_run(db_session, other_eng, other, status=RunStatus.RUNNING)

    items, total = await RunRepository(db_session).list_for_org(org.id)
    assert total == 2
    ids = {r.id for r in items}
    assert ids == {r_pending.id, r_running.id}
    # Newest first — ordered by (created_at, id) descending.
    assert items == sorted(items, key=lambda r: (r.created_at, r.id), reverse=True)

    # status filter narrows to one lifecycle state.
    items, total = await RunRepository(db_session).list_for_org(
        org.id, status=RunStatus.RUNNING
    )
    assert total == 1
    assert items[0].id == r_running.id


async def test_runs_list_for_org_paginates(db_session):
    org = await make_org(db_session)
    eng = await make_engagement(db_session, org)
    for _ in range(3):
        await _make_run(db_session, eng, org)

    items, total = await RunRepository(db_session).list_for_org(
        org.id, limit=2, offset=0
    )
    assert total == 3
    assert len(items) == 2
    items, total = await RunRepository(db_session).list_for_org(
        org.id, limit=2, offset=2
    )
    assert total == 3
    assert len(items) == 1


# ---------------------------------------------------------------------------
# FindingRepository.list_for_org
# ---------------------------------------------------------------------------
async def test_findings_list_for_org_isolates_and_filters(db_session):
    org = await make_org(db_session, slug="alpha")
    other = await make_org(db_session, slug="beta")
    eng = await make_engagement(db_session, org)
    other_eng = await make_engagement(db_session, other)
    run = await _make_run(db_session, eng, org)
    other_run = await _make_run(db_session, other_eng, other)

    f_crit_new = await _make_finding(
        db_session, run, eng, org,
        title="crit", severity=FindingSeverity.CRITICAL, status=FindingStatus.NEW,
    )
    f_low_verified = await _make_finding(
        db_session, run, eng, org,
        title="low", severity=FindingSeverity.LOW, status=FindingStatus.VERIFIED,
    )
    # Cross-org finding must never surface.
    await _make_finding(
        db_session, other_run, other_eng, other,
        title="other", severity=FindingSeverity.CRITICAL, status=FindingStatus.NEW,
    )

    items, total = await FindingRepository(db_session).list_for_org(org.id)
    assert total == 2
    assert {f.id for f in items} == {f_crit_new.id, f_low_verified.id}
    # Newest first — ordered by (created_at, id) descending.
    assert items == sorted(items, key=lambda f: (f.created_at, f.id), reverse=True)

    # severity filter.
    items, total = await FindingRepository(db_session).list_for_org(
        org.id, severity=FindingSeverity.CRITICAL
    )
    assert total == 1 and items[0].id == f_crit_new.id

    # status filter.
    items, total = await FindingRepository(db_session).list_for_org(
        org.id, status=FindingStatus.VERIFIED
    )
    assert total == 1 and items[0].id == f_low_verified.id

    # combined filters that match nothing.
    items, total = await FindingRepository(db_session).list_for_org(
        org.id, severity=FindingSeverity.LOW, status=FindingStatus.NEW
    )
    assert total == 0 and items == []


# ---------------------------------------------------------------------------
# OverviewRepository
# ---------------------------------------------------------------------------
async def test_overview_counts_are_correct_and_org_scoped(db_session):
    org = await make_org(db_session, slug="alpha")
    other = await make_org(db_session, slug="beta")

    # Engagements: default make_engagement is ACTIVE; add a DRAFT.
    from app.models.engagement import EngagementStatus

    eng_active = await make_engagement(db_session, org)
    await make_engagement(db_session, org, status=EngagementStatus.DRAFT)

    # Targets: one ATTESTED (default), one UNATTESTED.
    await make_target(db_session, org, value="a.example.com")
    await make_target(
        db_session, org, value="b.example.com",
        status=AttestationStatus.UNATTESTED, kind=TargetKind.DOMAIN,
    )

    # Runs: one PENDING, two RUNNING.
    await _make_run(db_session, eng_active, org, status=RunStatus.PENDING)
    await _make_run(db_session, eng_active, org, status=RunStatus.RUNNING)
    await _make_run(db_session, eng_active, org, status=RunStatus.RUNNING)

    run = await _make_run(db_session, eng_active, org, status=RunStatus.COMPLETED)
    # Findings: NEW (open), VERIFIED (open), FALSE_POSITIVE (not open).
    await _make_finding(db_session, run, eng_active, org, severity=FindingSeverity.HIGH, status=FindingStatus.NEW)
    await _make_finding(db_session, run, eng_active, org, severity=FindingSeverity.HIGH, status=FindingStatus.VERIFIED)
    await _make_finding(db_session, run, eng_active, org, severity=FindingSeverity.LOW, status=FindingStatus.FALSE_POSITIVE)

    # Noise in the OTHER org that must not be counted.
    other_eng = await make_engagement(db_session, other)
    other_run = await _make_run(db_session, other_eng, other, status=RunStatus.RUNNING)
    await make_target(db_session, other, value="z.example.com")
    await _make_finding(db_session, other_run, other_eng, other, status=FindingStatus.NEW)

    summary = await OverviewRepository(db_session).summary(org.id)

    assert summary["engagements"]["total"] == 2
    assert summary["engagements"]["active"] == 1
    assert summary["engagements"]["by_status"] == {"ACTIVE": 1, "DRAFT": 1}

    assert summary["targets"]["total"] == 2
    assert summary["targets"]["attested"] == 1
    assert summary["targets"]["by_status"] == {"ATTESTED": 1, "UNATTESTED": 1}

    assert summary["runs"]["total"] == 4
    assert summary["runs"]["running"] == 2
    assert summary["runs"]["by_status"] == {"PENDING": 1, "RUNNING": 2, "COMPLETED": 1}

    assert summary["findings"]["total"] == 3
    assert summary["findings"]["open"] == 2  # NEW + VERIFIED
    assert summary["findings"]["by_severity"] == {"HIGH": 2, "LOW": 1}

    # Validates cleanly into the response model.
    model = OverviewRead.model_validate(summary)
    assert model.findings.open == 2
    assert model.runs.running == 2


async def test_overview_empty_org_is_all_zeroes(db_session):
    org = await make_org(db_session)
    summary = await OverviewRepository(db_session).summary(org.id)
    model = OverviewRead.model_validate(summary)
    assert model.engagements.total == 0
    assert model.targets.total == 0
    assert model.runs.total == 0
    assert model.findings.total == 0
    assert model.findings.open == 0
    assert model.engagements.by_status == {}
