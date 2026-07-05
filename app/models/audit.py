"""AuditEvent — the append-only, hash-chained authorization/lifecycle log.

Immutable SOC2 evidence (spec §4/§5). Insert-only: it uses ``UUIDMixin`` for the
id but deliberately NOT ``TimestampMixin`` — there is only ``created_at`` and no
``updated_at``, because a row is never mutated. Tamper-evidence comes from the
``prev_hash -> event_hash`` chain (see ``app.audit.chain.compute_event_hash``).
The columns org_id/engagement_id/run_id/target_id are plain UUIDs with NO foreign
keys, so an audit row survives independently of the entities it references.
Phase 3 adds a DB trigger denying UPDATE/DELETE.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin

_JSONB = JSON().with_variant(JSONB(), "postgresql")


class AuditAction(str, enum.Enum):
    ENGAGEMENT_CREATED = "ENGAGEMENT_CREATED"
    ENGAGEMENT_ACTIVATED = "ENGAGEMENT_ACTIVATED"
    TARGET_REGISTERED = "TARGET_REGISTERED"
    TARGET_ATTESTED = "TARGET_ATTESTED"
    TARGET_REVOKED = "TARGET_REVOKED"
    SCOPE_CHECK_ALLOWED = "SCOPE_CHECK_ALLOWED"
    SCOPE_CHECK_DENIED = "SCOPE_CHECK_DENIED"
    RUN_STARTED = "RUN_STARTED"
    RUN_STOPPED = "RUN_STOPPED"
    RUN_COMPLETED = "RUN_COMPLETED"
    FINDING_RECORDED = "FINDING_RECORDED"
    FINDING_HANDOFF = "FINDING_HANDOFF"
    EMERGENCY_STOP = "EMERGENCY_STOP"
    ENTITLEMENT_DENIED = "ENTITLEMENT_DENIED"


def _enum(enum_cls: type[enum.Enum], name: str) -> sa.Enum:
    return sa.Enum(enum_cls, name=name, values_callable=lambda obj: [e.value for e in obj])


class AuditEvent(UUIDMixin, Base):
    """Append-only. No ``updated_at`` by construction (immutability)."""

    __tablename__ = "audit_events"

    # Scope columns are plain UUIDs (NO FK) so audit survives entity deletion.
    org_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid(), nullable=True, index=True)
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid(), nullable=True, index=True)
    run_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid(), nullable=True)

    action: Mapped[AuditAction] = mapped_column(_enum(AuditAction, "audit_action"), nullable=False)
    actor_id: Mapped[str] = mapped_column(Text, nullable=False)
    actor_email: Mapped[str | None] = mapped_column(Text, nullable=True)

    target: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid(), nullable=True)
    # allow | deny
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict | None] = mapped_column(_JSONB, nullable=True)

    # Hash chain (tamper-evidence). SHA-256 hex = 64 chars.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # Append-only: only created_at, defaulted server-side; no TimestampMixin / updated_at.
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AuditEvent id={self.id} action={getattr(self.action, 'value', self.action)} "
            f"decision={self.decision!r}>"
        )
