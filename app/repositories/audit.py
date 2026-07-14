"""AuditRepository — org-scoped access to the immutable audit trail.

The audit log is append-only and hash-chained, so this repository only reads it.
It powers the compliance / SIEM surfaces: a tenant-scoped event feed, a chain
integrity check, and control/posture rollups. Repositories never commit.
"""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.chain import verify_chain
from app.models.audit import AuditAction, AuditEvent


class AuditRepository:
    """Reads the immutable audit trail. Construct per-request with the session."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_org(
        self,
        org_id: uuid.UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[AuditEvent], int]:
        """Return ``(items, total)`` for one org's audit feed, newest first."""
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.org_id == org_id)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.event_hash.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.execute(stmt)).scalars().all())
        total = await self.session.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.org_id == org_id)
        )
        return items, int(total or 0)

    async def chain_for_org(self, org_id: uuid.UUID) -> list[AuditEvent]:
        """Return the full org-scoped audit chain, oldest first."""
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.org_id == org_id)
            .order_by(AuditEvent.created_at.asc(), AuditEvent.event_hash.asc())
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def compliance_snapshot(self, org_id: uuid.UUID, *, window_days: int = 30) -> dict:
        """Return a compact compliance + posture snapshot for one tenant."""
        chain = await self.chain_for_org(org_id)
        verified, broken_at = verify_chain(chain)
        head = chain[-1].event_hash if chain else None
        counts = Counter(getattr(event.action, "value", event.action) for event in chain)

        cutoff = datetime.now(timezone.utc) - timedelta(days=max(window_days, 1))
        recent = [
            event
            for event in chain
            if _as_utc(event.created_at) >= cutoff
        ]
        posture: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "total_events": 0,
                "allowed_scans": 0,
                "denied_scans": 0,
                "findings_recorded": 0,
                "triaged_findings": 0,
            }
        )
        for event in recent:
            day = event.created_at.date().isoformat()
            bucket = posture[day]
            bucket["total_events"] += 1
            action = getattr(event.action, "value", event.action)
            if action == AuditAction.SCOPE_CHECK_ALLOWED.value:
                bucket["allowed_scans"] += 1
            if action == AuditAction.SCOPE_CHECK_DENIED.value:
                bucket["denied_scans"] += 1
            if action == AuditAction.FINDING_RECORDED.value:
                bucket["findings_recorded"] += 1
            if action == AuditAction.FINDING_TRIAGED.value:
                bucket["triaged_findings"] += 1

        posture_rows = [
            {"date": day, **values}
            for day, values in sorted(posture.items())
        ]
        return {
            "chain_head_hash": head,
            "chain_verified": verified,
            "chain_break_index": broken_at,
            "event_count": len(chain),
            "by_action": dict(sorted(counts.items())),
            "posture": posture_rows,
        }


def _as_utc(value: datetime | None) -> datetime:
    """Normalize timestamps for cross-dialect comparisons."""
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
