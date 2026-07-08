"""Authorized-target + attestation schemas (spec §4/§6).

``TargetCreate`` registers a new (UNATTESTED) target; ``AttestationRequest`` is the
body of ``POST /targets/{id}/attest`` and its fields are unpacked directly into
``app.authz.attestation.attest_target`` (``method`` / ``checkbox_ack`` /
``typed_confirmation`` / ``evidence`` / ``expires_at``). ``TargetRead`` mirrors the
``app.models.target.AuthorizedTarget`` ORM columns 1:1.
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.target import AttestationMethod, AttestationStatus, TargetKind


class TargetCreate(BaseModel):
    """Register a new authorized target (starts UNATTESTED). ``org_id`` comes from
    the caller's org, not the body."""

    kind: TargetKind
    value: str = Field(min_length=1)
    label: str | None = None
    owner_principal: str | None = None


class AttestationRequest(BaseModel):
    """Attest a registered target so the gate will treat it as scannable.

    The route forwards every field to ``attest_target``; the authz layer enforces
    per-method requirements (e.g. checkbox + typed confirmation as the minimum,
    domain-ownership proof in ``evidence`` for external targets).
    """

    method: AttestationMethod
    checkbox_ack: bool = False
    typed_confirmation: str | None = None
    # Required for the admin-only SELF_ATTESTED / BREAK_GLASS methods: the written
    # basis for authorizing this target without an ownership proof (owned-infra note,
    # signed-engagement ref, IR/DFIR ticket). Recorded verbatim in the audit trail.
    justification: str | None = None
    evidence: dict[str, Any] | None = None
    expires_at: datetime | None = None


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    kind: TargetKind
    value: str
    label: str | None = None
    owner_principal: str | None = None
    attestation_status: AttestationStatus
    attestation_method: AttestationMethod | None = None
    attested_by: str | None = None
    attested_at: datetime | None = None
    attestation_evidence: dict[str, Any] | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
