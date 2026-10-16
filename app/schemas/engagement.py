"""Engagement + scope-of-engagement schemas (spec §4/§6).

These are the typed contract for the scope gate. ``EngagementScope`` and
``RulesOfEngagement`` are consumed directly by ``app.authz.gate`` (which calls
``EngagementScope.model_validate`` / ``RulesOfEngagement.model_validate`` on the
engagement's JSONB columns) and by ``app.authz.scope.target_in_scope`` — so the
field names here are load-bearing:

* the ``scope`` column persists ``{in_scope, exclusions}`` (see ``ScopeSelection``);
* rules-of-engagement live in a sibling ``rules_of_engagement`` column;
* the gate merges the two back into a full ``EngagementScope`` at evaluation time.

GOTCHA: any field named ``model_profile`` collides with Pydantic's protected
``model_`` namespace, so every model carrying it sets
``ConfigDict(protected_namespaces=())``.
"""

import logging
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.time import BUSINESS_TIMEZONE, normalize_datetime_to_utc
from app.models.engagement import EngagementStatus
from app.models.target import TargetKind

DEFAULT_MODEL_PROFILE = "hybrid-local-sweep-verify"
_time_logger = logging.getLogger("secops.schemas.time")


class ScopeRule(BaseModel):
    """One in-scope / exclusion rule: a typed asset the gate matches targets against.

    Mirrors what ``app.engine.strix_runner._rule_str`` and the scope matcher read
    off each rule (``kind`` + ``value``). ``kind`` is an optional hint (the
    matcher can infer from ``value``); ``value`` is the domain / URL / CIDR / repo
    (or a host/path pattern for exclusions).
    """

    model_config = ConfigDict(from_attributes=True)

    kind: TargetKind | None = None
    value: str = Field(min_length=1)
    description: str | None = None


class RulesOfEngagement(BaseModel):
    """Constraints on how a scan may run (spec §4).

    EVERY field is optional: the gate does ``RulesOfEngagement.model_validate({})``
    on a possibly-empty JSONB column and reads ``time_window_start`` /
    ``time_window_end`` back, so this must validate an empty dict cleanly and never
    reject well-formed stored data.
    """

    model_config = ConfigDict(from_attributes=True)

    intensity: str | None = None
    allowed_vuln_classes: list[str] = Field(default_factory=list)
    time_window_start: datetime | None = None
    time_window_end: datetime | None = None
    max_concurrency: int | None = None

    @field_validator("time_window_start", "time_window_end", mode="before")
    @classmethod
    def _normalize_time_window(cls, value: Any) -> Any:
        """Keep stored RoE boundaries as aware UTC, including legacy rows."""
        return normalize_datetime_to_utc(value)


class ScopeSelection(BaseModel):
    """The ``{in_scope, exclusions}`` half persisted in the engagement ``scope`` column."""

    model_config = ConfigDict(from_attributes=True)

    in_scope: list[ScopeRule] = Field(default_factory=list)
    exclusions: list[ScopeRule] = Field(default_factory=list)


class EngagementScope(ScopeSelection):
    """The full typed scope the gate evaluates: selection + rules-of-engagement.

    ``app.authz.gate._load_scope`` rebuilds this by merging the engagement's
    ``rules_of_engagement`` column back onto the ``scope`` column before validating.
    """

    rules_of_engagement: RulesOfEngagement = Field(default_factory=RulesOfEngagement)


class EngagementCreate(BaseModel):
    """Request body for ``POST /engagements`` — a DRAFT engagement + its scope.

    ``created_by`` and ``status`` are set server-side (from the actor / lifecycle),
    not accepted from the client.
    """

    model_config = ConfigDict(protected_namespaces=())

    name: str = Field(min_length=1, max_length=512)
    scope: EngagementScope
    model_profile: str = Field(default=DEFAULT_MODEL_PROFILE, max_length=255)
    starts_at: datetime | None = None
    expires_at: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_request_datetimes(cls, value: Any) -> Any:
        """Normalize every client datetime and warn once for this request."""
        if not isinstance(value, dict):
            return value

        data = dict(value)
        warned = False

        def warn_once() -> None:
            nonlocal warned
            if not warned:
                _time_logger.warning(
                    "naive client datetime interpreted as %s business time and normalized to UTC",
                    BUSINESS_TIMEZONE,
                )
                warned = True

        for field_name in ("starts_at", "expires_at"):
            if field_name in data:
                data[field_name] = normalize_datetime_to_utc(
                    data[field_name], on_naive=warn_once
                )

        scope = data.get("scope")
        if isinstance(scope, dict):
            scope = dict(scope)
            roe = scope.get("rules_of_engagement")
            if isinstance(roe, dict):
                roe = dict(roe)
                for field_name in ("time_window_start", "time_window_end"):
                    if field_name in roe:
                        roe[field_name] = normalize_datetime_to_utc(
                            roe[field_name], on_naive=warn_once
                        )
                scope["rules_of_engagement"] = roe
            data["scope"] = scope
        return data

    @field_validator("starts_at", "expires_at", mode="before")
    @classmethod
    def _normalize_lifecycle_datetime(cls, value: Any) -> Any:
        return normalize_datetime_to_utc(value)


class EngagementRead(BaseModel):
    """Serialized engagement (``EngagementRead.model_validate(engagement)``).

    ``scope`` reflects the stored ``{in_scope, exclusions}`` column and
    ``rules_of_engagement`` the sibling column, so the two are surfaced exactly as
    persisted (no empty-RoE duplication inside ``scope``).
    """

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    status: EngagementStatus
    scope: ScopeSelection
    rules_of_engagement: RulesOfEngagement
    model_profile: str
    created_by: str
    starts_at: datetime | None = None
    expires_at: datetime | None = None
    emergency_stopped: bool
    created_at: datetime
    updated_at: datetime


class ScopeCheckRequest(BaseModel):
    """Request body for the dry-run gate preview ``POST /engagements/{id}/scope/check``."""

    target: str = Field(min_length=1)


class ScopeDecisionRead(BaseModel):
    """Serialized authorization decision.

    Validated from an ``app.authz.dto.ScopeDecision`` via
    ``ScopeDecisionRead.model_validate(decision)`` (``from_attributes=True``), so
    the fields mirror that DTO exactly.
    """

    model_config = ConfigDict(from_attributes=True)

    allowed: bool
    code: str
    reason: str
    engagement_id: uuid.UUID
    target: str
    matched_target_id: uuid.UUID | None = None
    violations: list[str] = Field(default_factory=list)
