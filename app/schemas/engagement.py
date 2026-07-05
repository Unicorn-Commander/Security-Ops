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

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.engagement import EngagementStatus
from app.models.target import TargetKind

DEFAULT_MODEL_PROFILE = "hybrid-local-sweep-verify"


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
