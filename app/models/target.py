"""AuthorizedTarget — the registry the authorization gate consults.

A target (domain / URL / IP-range / repo) must be pre-registered AND attested by
an authorized principal before any scan can name it (spec §4). A target is
scannable only when ``app.authz.attestation.attestation_is_valid`` returns True
(status == ATTESTED, not revoked, not expired).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import ForeignKey, JSON, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:  # pragma: no cover
    from app.models.organization import Organization

# JSONB on Postgres, portable JSON elsewhere (tests run on aiosqlite).
_JSONB = JSON().with_variant(JSONB(), "postgresql")


class TargetKind(str, enum.Enum):
    """What kind of asset a target names; drives scope-rule matching in the gate."""

    DOMAIN = "DOMAIN"
    URL = "URL"
    IP_RANGE = "IP_RANGE"
    REPO = "REPO"
    # A container image reference (``registry/name:tag`` or a digest) — scanned by
    # the Trivy engine (``trivy image``). Added for engine #4; see migration
    # ``0008_target_kind_image`` and ``app/engine/trivy_runner.py``.
    IMAGE = "IMAGE"


class AttestationMethod(str, enum.Enum):
    """How ownership/authorization was proven. External DOMAIN/URL/IP_RANGE targets
    require a domain-ownership proof (DNS_TXT / FILE_DROP / HTTP_HEADER); CHECKBOX +
    TYPED_CONFIRMATION are the minimum for all; OWNED = self-owned suite asset.

    Two admin-only "authorized-operator" methods skip the live ownership proof in
    favor of a recorded human authorization (spec §4, break-glass extension) — both
    are org-ADMIN-gated, require a written justification, are time-boxed, and are
    written to the immutable audit log exactly like a proven attestation:

    * ``SELF_ATTESTED`` — an admin authorizes a target on their own responsibility
      (owned infra, signed engagement) instead of proving ownership via DNS/HTTP.
    * ``BREAK_GLASS`` — the emergency red-team / DFIR path: authorize *any* target
      with a stated justification, no ownership proof. Gated behind an install-time
      switch (``settings.attestation_allow_break_glass``), admin-only, short TTL,
      and recorded under its own ``TARGET_BREAK_GLASS`` audit action so every use is
      independently alertable. Accountability (who/when/why) is preserved by design;
      only the ownership-proof *friction* is removed.
    """

    CHECKBOX = "CHECKBOX"
    TYPED_CONFIRMATION = "TYPED_CONFIRMATION"
    DNS_TXT = "DNS_TXT"
    FILE_DROP = "FILE_DROP"
    HTTP_HEADER = "HTTP_HEADER"
    OWNED = "OWNED"
    SELF_ATTESTED = "SELF_ATTESTED"
    BREAK_GLASS = "BREAK_GLASS"


class AttestationStatus(str, enum.Enum):
    """Lifecycle of a target's authorization."""

    UNATTESTED = "UNATTESTED"
    ATTESTED = "ATTESTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


def _enum(enum_cls: type[enum.Enum], name: str) -> sa.Enum:
    """Native PG enum that persists the member ``.value`` (== name here), so DB
    storage matches the migration's ``postgresql.ENUM`` labels and Pydantic output."""

    return sa.Enum(enum_cls, name=name, values_callable=lambda obj: [e.value for e in obj])


class AuthorizedTarget(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "authorized_targets"
    __table_args__ = (
        # A given (org, kind, value) is registered once. Convention -> uq_authorized_targets_org_id.
        UniqueConstraint("org_id", "kind", "value"),
    )

    org_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("organizations.id"), nullable=False, index=True
    )
    kind: Mapped[TargetKind] = mapped_column(_enum(TargetKind, "target_kind"), nullable=False)
    # Canonical value: domain / URL / CIDR / repo-url.
    value: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Who owns / authorized this asset (principal id or email).
    owner_principal: Mapped[str | None] = mapped_column(Text, nullable=True)

    attestation_status: Mapped[AttestationStatus] = mapped_column(
        _enum(AttestationStatus, "attestation_status"),
        nullable=False,
        default=AttestationStatus.UNATTESTED,
        server_default=AttestationStatus.UNATTESTED.value,
    )
    attestation_method: Mapped[AttestationMethod | None] = mapped_column(
        _enum(AttestationMethod, "attestation_method"), nullable=True
    )
    attested_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    attested_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    # DNS-TXT / file-drop / header proof payload.
    attestation_evidence: Mapped[dict | None] = mapped_column(_JSONB, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    org: Mapped["Organization"] = relationship("Organization", back_populates="targets")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AuthorizedTarget id={self.id} kind={getattr(self.kind, 'value', self.kind)} "
            f"value={self.value!r} status={getattr(self.attestation_status, 'value', self.attestation_status)}>"
        )
