"""app.authz.dto — the authorization gate's decision DTO (spec §4).

A single, transport-agnostic value object produced by the scope evaluator and
consumed by three places, each of which pins its shape:

* :func:`app.authz.gate.check_scope` / the internal ``_evaluate_scope`` build one
  via keyword args and return it;
* :func:`app.authz.audit.record_scope_decision` reads ``allowed`` / ``code`` /
  ``reason`` / ``engagement_id`` / ``target`` / ``matched_target_id`` /
  ``violations`` off it to write EXACTLY ONE audit row;
* ``app.schemas.engagement.ScopeDecisionRead`` is ``model_validate``-d directly
  from an instance (``from_attributes=True``), so the field names here are the
  wire contract for ``POST /engagements/{id}/scope/check``.

It is a pure decision record: immutable (``frozen``) and free of any DB / ORM /
FastAPI dependency, so it can be constructed and asserted on in isolation.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field


class ScopeDecision(BaseModel):
    """The outcome of evaluating one concrete ``target`` against an engagement.

    ``allowed`` is the verdict; ``code`` is the machine-readable reason slug that
    maps 1:1 to a concrete :class:`app.authz.errors.AuthorizationDenied` subclass
    on denial (and to :data:`app.authz.gate.ALLOWED_CODE` on success); ``reason``
    is the human-readable cause. ``matched_target_id`` is the covering
    :class:`~app.models.target.AuthorizedTarget` that authorized (or, when denied
    for an expired attestation, was implicated in) the decision. ``violations`` is
    a list of fine-grained cause tags preserved in the audit ``detail`` for SOC2
    export / forensics.
    """

    model_config = ConfigDict(frozen=True, from_attributes=True)

    allowed: bool
    code: str
    reason: str
    engagement_id: uuid.UUID
    target: str
    matched_target_id: uuid.UUID | None = None
    violations: list[str] = Field(default_factory=list)


__all__ = ["ScopeDecision"]
