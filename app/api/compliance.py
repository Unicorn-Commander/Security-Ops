"""Compliance / SIEM read surface.

The routes here are read-only and tenant-scoped through ``CurrentOrg``. They
expose the immutable audit trail for SIEM export and a compact posture snapshot
for continuous-control monitoring and evidence collection.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import CurrentOrg, DbSession
from app.repositories.audit import AuditRepository
from app.schemas.compliance import (
    AuditEventPageRead,
    AuditEventRead,
    ComplianceAuditRead,
    ComplianceControlRead,
    ComplianceOverviewRead,
)

router = APIRouter(tags=["compliance"])

_CONTROL_MAP = [
    ComplianceControlRead(
        framework="SOC 2",
        control="CC7.2",
        title="Detect and respond to unauthorized or out-of-scope activity",
        status="evidence_ready",
        evidence=[
            "SCOPE_CHECK_ALLOWED / SCOPE_CHECK_DENIED audit rows",
            "gate-enforced scan authorization",
            "tenant-scoped run and finding records",
        ],
    ),
    ComplianceControlRead(
        framework="SOC 2",
        control="CC8.1",
        title="Authorize and log security-relevant changes",
        status="evidence_ready",
        evidence=[
            "hash-chained audit_events",
            "append-only prev_hash -> event_hash chain",
            "audit trail integrity verification",
        ],
    ),
    ComplianceControlRead(
        framework="HIPAA",
        control="164.312(b)",
        title="Audit controls",
        status="evidence_ready",
        evidence=[
            "org-scoped audit feed",
            "immutable audit event export",
            "SIEM-friendly JSON shape",
        ],
    ),
    ComplianceControlRead(
        framework="HIPAA",
        control="164.312(c)(1)",
        title="Integrity",
        status="evidence_ready",
        evidence=[
            "hash chain verification on audit events",
            "tamper-evident event_hash / prev_hash links",
        ],
    ),
]


def _audit_summary(snapshot: dict) -> ComplianceAuditRead:
    return ComplianceAuditRead(
        chain_head_hash=snapshot["chain_head_hash"],
        chain_verified=bool(snapshot["chain_verified"]),
        chain_break_index=snapshot["chain_break_index"],
        event_count=int(snapshot["event_count"]),
        by_action=dict(snapshot["by_action"]),
    )


@router.get("/compliance", response_model=ComplianceOverviewRead)
async def compliance_overview_route(
    session: DbSession,
    org: CurrentOrg,
) -> ComplianceOverviewRead:
    snapshot = await AuditRepository(session).compliance_snapshot(org.id)
    return ComplianceOverviewRead(
        audit=_audit_summary(snapshot),
        posture=snapshot["posture"],
        controls=list(_CONTROL_MAP),
    )


@router.get("/compliance/audit-events", response_model=AuditEventPageRead)
async def compliance_audit_events_route(
    session: DbSession,
    org: CurrentOrg,
    limit: int = 100,
    offset: int = 0,
) -> AuditEventPageRead:
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    items, total = await AuditRepository(session).list_for_org(org.id, limit=limit, offset=offset)
    return AuditEventPageRead(
        items=[AuditEventRead.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )
