"""EngagementRepository — data access for :class:`app.models.engagement.Engagement`.

Thin async-SQLAlchemy-2.0 data-access layer. Repositories NEVER commit — the
caller (service / route / the authorization gate) owns the transaction (see
``app.db.session.get_session``). Callers:

* ``app.authz.gate`` loads the engagement via :meth:`get` to gate a run.
* ``app.api.engagements`` uses :meth:`get` (tenant-checked in the route) and
  :meth:`list_for_org` for the paginated engagement list.

Dependency direction (no cycles): repositories -> {models, db}. Repositories do
not import authz / services / api.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.engagement import Engagement


class EngagementRepository:
    """Reads engagements. Construct per-request with the active session."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, engagement_id: uuid.UUID) -> Engagement | None:
        """Return the engagement by primary key, or ``None`` if it does not exist.

        Tenant isolation (``org_id`` check) is the caller's responsibility — the
        gate and routes compare ``engagement.org_id`` against the current org.
        """
        return await self.session.get(Engagement, engagement_id)

    async def list_for_org(
        self,
        org_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Engagement], int]:
        """Return ``(items, total)`` for one org's engagements, newest first.

        ``total`` is the unpaginated count so the API can render a ``Page``.
        """
        stmt = (
            select(Engagement)
            .where(Engagement.org_id == org_id)
            .order_by(Engagement.created_at.desc(), Engagement.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.execute(stmt)).scalars().all())
        total = await self.session.scalar(
            select(func.count()).select_from(Engagement).where(Engagement.org_id == org_id)
        )
        return items, int(total or 0)
