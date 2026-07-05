"""OverviewRepository — org-scoped dashboard counts for the console (spec §6).

Thin async-SQLAlchemy-2.0 data-access layer; repositories NEVER commit (a read
has no transaction boundary to own). The new console's landing page needs a
single cheap summary of a tenant's estate — engagement / target / run / finding
totals broken down by lifecycle state — without paging through every row.

Every query here is a ``GROUP BY`` aggregate filtered by ``org_id`` (the
denormalized tenant column on all four tables), so:

* tenant isolation is the WHERE clause itself — a caller can only ever count
  their own org's rows, never another tenant's;
* no full ORM rows are loaded — each table costs exactly one grouped
  ``COUNT(*)`` round-trip, independent of how many engagements/findings exist.

The route/service reads the returned ``{status_value: count}`` maps and folds
them into the typed ``OverviewRead`` response. Callers pass an already
tenant-resolved ``org_id`` (``CurrentOrg.id``).

Dependency direction (no cycles): repositories -> {models, db}.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.engagement import Engagement, EngagementStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.run import Run, RunStatus
from app.models.target import AttestationStatus, AuthorizedTarget

# Findings a client still needs to act on: confirmed-or-new, not yet triaged away.
_OPEN_FINDING_STATUSES = (FindingStatus.NEW, FindingStatus.VERIFIED)


class OverviewRepository:
    """Computes org-scoped dashboard counts. Construct per-request with the session."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _count_by(self, column, org_column, org_id: uuid.UUID) -> dict[str, int]:
        """Return ``{enum_value: count}`` grouping one table's rows by ``column``.

        One ``SELECT column, COUNT(*) ... WHERE org = :org GROUP BY column`` — no
        rows materialized. Enum keys are surfaced by their ``.value`` (the string
        stored in the DB) so the JSON shape is stable regardless of dialect.
        """
        stmt = (
            select(column, func.count())
            .where(org_column == org_id)
            .group_by(column)
        )
        rows = (await self.session.execute(stmt)).all()
        out: dict[str, int] = {}
        for key, count in rows:
            out[getattr(key, "value", key)] = int(count)
        return out

    async def engagements_summary(self, org_id: uuid.UUID) -> dict:
        by_status = await self._count_by(
            Engagement.status, Engagement.org_id, org_id
        )
        return {
            "total": sum(by_status.values()),
            "by_status": by_status,
            "active": by_status.get(EngagementStatus.ACTIVE.value, 0),
        }

    async def targets_summary(self, org_id: uuid.UUID) -> dict:
        by_status = await self._count_by(
            AuthorizedTarget.attestation_status, AuthorizedTarget.org_id, org_id
        )
        return {
            "total": sum(by_status.values()),
            "attested": by_status.get(AttestationStatus.ATTESTED.value, 0),
            "by_status": by_status,
        }

    async def runs_summary(self, org_id: uuid.UUID) -> dict:
        by_status = await self._count_by(Run.status, Run.org_id, org_id)
        return {
            "total": sum(by_status.values()),
            "by_status": by_status,
            "running": by_status.get(RunStatus.RUNNING.value, 0),
        }

    async def findings_summary(self, org_id: uuid.UUID) -> dict:
        by_severity = await self._count_by(
            Finding.severity, Finding.org_id, org_id
        )
        open_count = await self.session.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.org_id == org_id,
                Finding.status.in_(_OPEN_FINDING_STATUSES),
            )
        )
        return {
            "total": sum(by_severity.values()),
            "by_severity": by_severity,
            "open": int(open_count or 0),
        }

    async def summary(self, org_id: uuid.UUID) -> dict:
        """Return the full dashboard summary for one org (four grouped counts)."""
        return {
            "engagements": await self.engagements_summary(org_id),
            "targets": await self.targets_summary(org_id),
            "runs": await self.runs_summary(org_id),
            "findings": await self.findings_summary(org_id),
        }
