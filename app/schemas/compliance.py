"""Compliance / SIEM read schemas for the org-scoped security console."""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    action: str
    actor_id: str
    actor_email: str | None
    org_id: UUID | None
    engagement_id: UUID | None
    run_id: UUID | None
    target: str | None
    target_id: UUID | None
    decision: str | None
    reason: str | None
    detail: dict | None
    prev_hash: str | None
    event_hash: str


class AuditEventPageRead(BaseModel):
    items: list[AuditEventRead]
    total: int
    limit: int
    offset: int


class ComplianceControlRead(BaseModel):
    framework: str
    control: str
    title: str
    status: str
    evidence: list[str]


class PostureBucketRead(BaseModel):
    date: date
    total_events: int
    allowed_scans: int
    denied_scans: int
    findings_recorded: int
    triaged_findings: int


class ComplianceAuditRead(BaseModel):
    chain_head_hash: str | None
    chain_verified: bool
    chain_break_index: int | None
    event_count: int
    by_action: dict[str, int]


class ComplianceOverviewRead(BaseModel):
    audit: ComplianceAuditRead
    posture: list[PostureBucketRead]
    controls: list[ComplianceControlRead]
