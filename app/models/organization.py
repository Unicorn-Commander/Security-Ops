"""Organization — the tenant root for Security-Ops.

Every authorized target, engagement, run, finding, and audit event is scoped to
an organization. Phase 3 attaches Postgres row-level-security policies keyed on
``org_id`` across all child tables (spec §5, "no org-level RLS in suite today —
add before multi-tenant GA"). Phase 1 ships a single pilot org.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:  # pragma: no cover - typing only, resolved via the mapper registry at runtime
    from app.models.engagement import Engagement
    from app.models.target import AuthorizedTarget


class Organization(UUIDMixin, TimestampMixin, Base):
    """A customer tenant. ``slug`` is the stable external identifier used to map
    an SSO principal (via ``org_slug`` / a realm attribute) onto its org."""

    __tablename__ = "organizations"

    slug: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Optional Keycloak group this org maps to (suite convention); nullable in Phase 1.
    keycloak_group: Mapped[str | None] = mapped_column(Text, nullable=True)

    targets: Mapped[list["AuthorizedTarget"]] = relationship(
        "AuthorizedTarget", back_populates="org"
    )
    engagements: Mapped[list["Engagement"]] = relationship(
        "Engagement", back_populates="org"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug convenience
        return f"<Organization id={self.id} slug={self.slug!r}>"
