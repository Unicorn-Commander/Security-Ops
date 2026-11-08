"""Organization-scoped credentials for external finding deliveries.

An ingest source is a deliberately small credential record.  The receiver needs
to compare the stored webhook secret against a request before it knows the
request's organization, so it enumerates organization ids (the bootstrap table
is intentionally not RLS-protected), binds each normal org context in turn, and
reads sources through the same fail-closed RLS policy as every other tenant
table.

The secret is stored as the minted ``whsec_`` value.  There is no at-rest
encryption helper in this repository; the operator API returns it only at mint
or rotation time and all ordinary reads omit it.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin


class IngestSource(UUIDMixin, Base):
    """One organization-owned external webhook credential."""

    __tablename__ = "ingest_sources"

    org_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(), ForeignKey("organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(
        String(64), nullable=False, default="center-deep", server_default="center-deep"
    )
    # Plain storage is intentional until this application has a shared at-rest
    # encryption facility.  The receiver must recover the key to verify HMAC.
    secret: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )
    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_delivery_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_webhook_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging convenience
        return f"<IngestSource id={self.id} org_id={self.org_id} kind={self.kind!r}>"


__all__ = ["IngestSource"]
