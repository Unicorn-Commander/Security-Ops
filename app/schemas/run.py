"""Run schemas (spec §4/§6/§7).

``RunCreate`` is the body of the GATE-ENFORCED ``POST /engagements/{id}/runs``:
``app.services.runs.start_run`` runs ``app.authz.gate.enforce_scope`` for every
entry in ``targets`` before any run row is created. ``RunRead.model_validate(run)``
serializes the ORM row.

GOTCHA: ``model_profile`` collides with Pydantic's protected ``model_`` namespace,
so both models set ``ConfigDict(protected_namespaces=())``.
"""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.run import RunMode, RunStatus


class RunCreate(BaseModel):
    """Start a scan run over a set of concrete, gate-checked targets.

    ``model_profile`` is optional here: when omitted the service falls back to the
    engagement's profile. ``engagement_id`` / ``org_id`` come from the route + org,
    not the body.
    """

    model_config = ConfigDict(protected_namespaces=())

    targets: list[str] = Field(min_length=1)
    mode: RunMode = RunMode.STANDARD
    model_profile: str | None = None
    # Which scan engine runs this. ``strix`` (default) = autonomous agent;
    # ``nuclei`` = templated web breadth scanner; ``gitleaks`` = repo secret scanner
    # (REPO targets); ``trivy`` = CVE/SCA/misconfig/secret scanner (IMAGE or REPO
    # targets). All ride the same server-side authorization gate.
    engine: str = "strix"

    @field_validator("targets")
    @classmethod
    def _clean_targets(cls, value: list[str]) -> list[str]:
        cleaned = [t.strip() for t in value if isinstance(t, str) and t.strip()]
        if not cleaned:
            raise ValueError("at least one non-empty target is required")
        return cleaned

    @field_validator("engine")
    @classmethod
    def _known_engine(cls, value: str) -> str:
        v = (value or "strix").strip().lower()
        if v not in ("strix", "nuclei", "gitleaks", "trivy"):
            raise ValueError("engine must be 'strix', 'nuclei', 'gitleaks', or 'trivy'")
        return v


class RunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: uuid.UUID
    engagement_id: uuid.UUID
    # Denormalized for RLS + the tenant checks in the routers.
    org_id: uuid.UUID
    # Strix's own run id (set in Phase 2).
    strix_run_id: str | None = None
    # Which engine ran this (strix | nuclei | gitleaks | trivy).
    engine: str = "strix"
    mode: RunMode
    model_profile: str
    targets: list[str] = Field(default_factory=list)
    status: RunStatus
    started_at: datetime | None = None
    ended_at: datetime | None = None
    cost_usd: Decimal | None = None
    usage: dict[str, Any] | None = None
    # Filesystem location of the Strix report bundle (./strix_runs/<run>/).
    report_path: str | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime
