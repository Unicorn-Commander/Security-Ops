"""Finding schema (spec §5/§6/§8).

Read-only in Phase 1 — findings are populated by the Phase 2 Strix runner. The
routers use ``FindingRead.model_validate(finding)``, so this mirrors the
``app.models.finding.Finding`` ORM columns 1:1 (``from_attributes=True``).
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.finding import FindingSeverity, FindingStatus


class FindingStatusUpdate(BaseModel):
    """Operator triage request — set a finding's status (spec §6).

    The body for ``POST /findings/{id}/status`` and the MCP ``findings_set_status``
    tool. Only operator-settable targets are honored by the service
    (``set_finding_status`` rejects ``HANDED_OFF``, which belongs to the hand-off
    flow); the value is validated against the ``FindingStatus`` enum here.
    """

    status: FindingStatus
    closure_reason: str | None = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    run_id: uuid.UUID
    # Denormalized for report scoping / RLS + the tenant checks in the routers.
    engagement_id: uuid.UUID
    org_id: uuid.UUID
    title: str
    severity: FindingSeverity
    cwe: str | None = None
    endpoint: str | None = None
    payload: str | None = None
    evidence: dict[str, Any] | None = None
    fingerprint: str | None = None
    poc: str | None = None
    # Model/profile that confirmed the finding in the hybrid sweep+verify flow.
    verified_by: str | None = None
    status: FindingStatus
    # Brigade ticket / PR id once handed off.
    handoff_ref: str | None = None
    closure_reason: str | None = None
    closed_by: str | None = None
    closed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
