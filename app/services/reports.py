"""Engagement report service (spec §8) — orchestration for the report export.

Loads the rows the pure assembler needs (the engagement's runs + findings via the
repositories), reads the Strix ``penetration_test_report.md`` for the latest
completed run (the trustworthy, frontier-verified client-facing pass — spec §8),
and hands everything to :func:`app.reports.builder.build_engagement_report` with an
injected ``generated_at``. The builder stays pure; this layer owns the I/O (DB
reads + the one report-file read) and the clock.

This operation is **read-only**: no rows are mutated and nothing is committed
(repositories never commit; a read has no transaction boundary to own). Tenant
isolation is the *caller's* responsibility — ``app.api.engagements`` loads the
engagement through the tenant-checked ``_load_engagement`` before calling here, so
the engagement passed in is already proven to belong to the requesting org.

Dependency direction (no cycles): services -> {reports, repositories, models,
core.config}. Nothing there imports services.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.run import RunStatus
from app.reports.builder import build_engagement_report, read_strix_report
from app.repositories.findings import FindingRepository
from app.repositories.runs import RunRepository

if TYPE_CHECKING:  # typing only — no runtime coupling / cycle
    from app.models.engagement import Engagement
    from app.models.finding import Finding
    from app.models.run import Run

logger = logging.getLogger("secops.services.reports")


async def generate_engagement_report(
    session: AsyncSession,
    *,
    engagement: "Engagement",
    config: Settings | None = None,
) -> str:
    """Build the branded Markdown report for an already-tenant-checked engagement.

    Loads the engagement's runs (newest first) and every finding, groups findings
    by run, reads the Strix report of the most recent COMPLETED run (if any), and
    calls the pure builder with ``generated_at=now``. Read-only — no commit.
    """
    runs = await RunRepository(session).list_for_engagement(engagement.id)
    findings, _total = await FindingRepository(session).list_for_engagement(
        engagement.id
    )

    findings_by_run: dict = {}
    for finding in findings:
        findings_by_run.setdefault(finding.run_id, []).append(finding)

    strix_report_text = _latest_completed_report(runs)

    logger.info(
        "reports.generate engagement=%s runs=%d findings=%d strix_report=%s",
        engagement.id,
        len(runs),
        len(findings),
        strix_report_text is not None,
    )
    return build_engagement_report(
        engagement,
        runs,
        findings_by_run,
        generated_at=datetime.now(timezone.utc),
        strix_report_text=strix_report_text,
        config=config,
    )


def _latest_completed_report(runs: list["Run"]) -> str | None:
    """Read the Strix report of the newest COMPLETED run that has one on disk.

    ``runs`` is newest-first (repository order), so the first COMPLETED run with a
    readable report wins. Falls through to ``None`` when no completed run produced a
    report — the pure builder still renders the summary without an engine section.
    """
    for run in runs:
        if run.status == RunStatus.COMPLETED:
            text = read_strix_report(run)
            if text is not None:
                return text
    return None


__all__ = ["generate_engagement_report"]
