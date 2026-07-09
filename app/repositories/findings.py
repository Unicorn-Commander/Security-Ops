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

import hashlib
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus


class FindingRepository:
    """Reads and creates findings. Construct per-request with the session."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.last_create_deduped = False
        self.dedup_count = 0

    @staticmethod
    def _normalize_fingerprint_text(value: object) -> str:
        text = "" if value is None else str(value)
        return " ".join(text.strip().lower().split())

    @classmethod
    def _fingerprint(
        cls,
        *,
        engine: object,
        cwe_or_cve: object,
        endpoint: object,
        title: object,
    ) -> str:
        material = "|".join(
            [
                cls._normalize_fingerprint_text(cwe_or_cve),
                cls._normalize_fingerprint_text(endpoint),
                cls._normalize_fingerprint_text(title),
            ]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:64]

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

    async def list_for_org(
        self,
        org_id: uuid.UUID,
        *,
        severity: FindingSeverity | None = None,
        status: FindingStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Finding], int]:
        """Return ``(items, total)`` for one org's findings inbox, newest first.

        Org-scoped console list (spec §6): filters on the denormalized ``org_id``
        so a caller only ever sees their own tenant's findings — tenant isolation
        is the WHERE clause itself, not a post-hoc check. Optional ``severity`` and
        ``status`` filters narrow the inbox (e.g. only CRITICAL, or only NEW).
        ``total`` is the unpaginated count of the same predicate so the API can
        render a ``Page``. Read-only; never commits.
        """
        predicate = [Finding.org_id == org_id]
        if severity is not None:
            predicate.append(Finding.severity == severity)
        if status is not None:
            predicate.append(Finding.status == status)
        stmt = (
            select(Finding)
            .where(*predicate)
            .order_by(Finding.created_at.desc(), Finding.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.execute(stmt)).scalars().all())
        total = await self.session.scalar(
            select(func.count()).select_from(Finding).where(*predicate)
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
        fingerprint: str | None = None,
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
        engine = None
        if isinstance(evidence, dict):
            engine = evidence.get("engine")
        cwe_or_cve = cwe
        if not cwe_or_cve and isinstance(evidence, dict):
            cwe_or_cve = evidence.get("cve")
        fingerprint = fingerprint or self._fingerprint(
            engine=engine or "strix",
            cwe_or_cve=cwe_or_cve,
            endpoint=endpoint,
            title=title,
        )

        stmt = select(Finding).where(
            Finding.engagement_id == engagement_id,
            Finding.fingerprint == fingerprint,
        )
        existing = (await self.session.execute(stmt)).scalars().first()
        self.last_create_deduped = existing is not None
        if existing is not None:
            if isinstance(existing.evidence, dict):
                evidence_dict = dict(existing.evidence)
            else:
                evidence_dict = {}
            also_found_by = []
            raw_also = evidence_dict.get("also_found_by")
            if isinstance(raw_also, list):
                also_found_by = [str(x) for x in raw_also if x]
            engine_name = str(engine or "strix")
            if engine_name not in also_found_by:
                also_found_by.append(engine_name)
            evidence_dict["also_found_by"] = also_found_by
            existing.evidence = evidence_dict
            await self.session.flush()
            self.dedup_count += 1
            return existing

        finding = Finding(
            run_id=run_id,
            engagement_id=engagement_id,
            org_id=org_id,
            title=title,
            severity=severity,
            cwe=cwe,
            endpoint=endpoint,
            fingerprint=fingerprint,
            payload=payload,
            evidence=evidence,
            poc=poc,
            verified_by=verified_by,
            status=status,
            handoff_ref=handoff_ref,
        )
        self.session.add(finding)
        await self.session.flush()
        self.last_create_deduped = False
        return finding
