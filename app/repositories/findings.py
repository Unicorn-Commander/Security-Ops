"""FindingRepository — data access for :class:`app.models.finding.Finding`.

Thin async-SQLAlchemy-2.0 data-access layer; repositories NEVER commit (the
caller owns the transaction — the Strix runner commits at run-lifecycle
boundaries). Callers:

* ``app.api.findings`` / ``app.api.runs`` use :meth:`get` (tenant-checked in the
  route) and :meth:`list_for_run` for the paginated per-run findings list.
* ``app.engine.strix_runner`` persists parsed vulnerabilities via :meth:`create`
  (kwargs mirror ``ParsedVulnerability.to_finding_fields`` — the denormalized
  ``run_id`` / ``engagement_id`` / ``org_id`` per the findings table).

Dependency direction (no cycles): repositories -> {models, db}.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus


class FindingRepository:
    """Reads and creates findings. Construct per-request with the session."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, finding_id: uuid.UUID) -> Finding | None:
        """Return the finding by primary key, or ``None``. Tenant isolation
        (``org_id`` check) is enforced by the caller (routes)."""
        return await self.session.get(Finding, finding_id)

    async def list_for_run(
        self,
        run_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Finding], int]:
        """Return ``(items, total)`` for one run's findings, newest first."""
        stmt = (
            select(Finding)
            .where(Finding.run_id == run_id)
            .order_by(Finding.created_at.desc(), Finding.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.execute(stmt)).scalars().all())
        total = await self.session.scalar(
            select(func.count()).select_from(Finding).where(Finding.run_id == run_id)
        )
        return items, int(total or 0)

    async def list_for_engagement(
        self,
        engagement_id: uuid.UUID,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> tuple[list[Finding], int]:
        """Return ``(items, total)`` for one engagement's findings, newest first.

        Aggregates findings across all of the engagement's runs (the denormalized
        ``engagement_id`` on each finding makes this a single-table query — no join).
        Tenant isolation (``org_id`` check) is the caller's job, as elsewhere; the
        report service loads the engagement tenant-checked first. The default limit
        is deliberately high (report scope, not a paged UI list)."""
        stmt = (
            select(Finding)
            .where(Finding.engagement_id == engagement_id)
            .order_by(Finding.created_at.desc(), Finding.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.execute(stmt)).scalars().all())
        total = await self.session.scalar(
            select(func.count())
            .select_from(Finding)
            .where(Finding.engagement_id == engagement_id)
        )
        return items, int(total or 0)

    async def create(
        self,
        *,
        run_id: uuid.UUID,
        engagement_id: uuid.UUID,
        org_id: uuid.UUID,
        title: str,
        severity: FindingSeverity,
        cwe: str | None = None,
        endpoint: str | None = None,
        payload: str | None = None,
        evidence: dict | None = None,
        poc: str | None = None,
        verified_by: str | None = None,
        status: FindingStatus = FindingStatus.NEW,
        handoff_ref: str | None = None,
    ) -> Finding:
        """Insert one finding and return it (flushed, so ``id`` is populated).

        Does not commit — the runner flushes/commits at its own lifecycle
        boundaries. The denormalized ``engagement_id`` / ``org_id`` are stored
        alongside ``run_id`` for report scoping and Phase-3 row-level security.
        """
        finding = Finding(
            run_id=run_id,
            engagement_id=engagement_id,
            org_id=org_id,
            title=title,
            severity=severity,
            cwe=cwe,
            endpoint=endpoint,
            payload=payload,
            evidence=evidence,
            poc=poc,
            verified_by=verified_by,
            status=status,
            handoff_ref=handoff_ref,
        )
        self.session.add(finding)
        await self.session.flush()
        return finding
