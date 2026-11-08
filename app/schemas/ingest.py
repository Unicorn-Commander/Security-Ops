"""Schemas for ingest-source administration and Center Deep deliveries."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class IngestSourceCreate(BaseModel):
    """Operator input for minting a Center Deep source."""

    name: str = Field(min_length=1, max_length=255)
    kind: Literal["center-deep"] = "center-deep"


class IngestSourceRead(BaseModel):
    """Non-secret source metadata safe for list/get responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    kind: str
    created_by: str
    created_at: datetime
    rotated_at: datetime | None = None
    last_delivery_at: datetime | None = None
    last_webhook_id: str | None = None
    disabled_at: datetime | None = None


class IngestSourceCreated(IngestSourceRead):
    """Source metadata plus the secret returned exactly once at mint/rotation."""

    secret: str


class CenterDeepSituation(BaseModel):
    """The situation payload emitted by Center Deep's vulnerability watch."""

    model_config = ConfigDict(extra="allow")

    feed: str | None = None
    state: str | None = None
    observed_at: str | None = None
    complete: bool | None = None
    inventory: list[dict[str, Any]] = Field(default_factory=list)
    kev_matches: list[dict[str, Any]] = Field(default_factory=list)
    releases: list[dict[str, Any]] = Field(default_factory=list)
    comparisons: list[dict[str, Any]] = Field(default_factory=list)


class CenterDeepWebhookData(BaseModel):
    """The signed webhook's data envelope."""

    model_config = ConfigDict(extra="allow")

    monitor_id: str | None = None
    run_id: str = Field(min_length=1)
    question: str | None = None
    status: str | None = None
    kind: str | None = None
    reason: str | None = None
    drift: bool | None = None
    report_url: str | None = None
    situation: CenterDeepSituation | None = None


class CenterDeepWebhook(BaseModel):
    """Validated body for ``monitor.run.completed``."""

    model_config = ConfigDict(extra="allow")

    type: str
    id: str = Field(min_length=1)
    timestamp: str | None = None
    data: CenterDeepWebhookData


class IngestDeliveryResponse(BaseModel):
    """Successful delivery result."""

    findings_created: int
    findings_seen: int
    run_id: uuid.UUID


class IngestDuplicateResponse(BaseModel):
    """Idempotent response for a repeated webhook attempt."""

    duplicate: Literal[True] = True


__all__ = [
    "CenterDeepSituation",
    "CenterDeepWebhook",
    "CenterDeepWebhookData",
    "IngestDeliveryResponse",
    "IngestDuplicateResponse",
    "IngestSourceCreate",
    "IngestSourceCreated",
    "IngestSourceRead",
]
