"""Campaign repository — data access for the campaign lifecycle."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign


class CampaignRepository:
    """Data access for Campaign rows."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, campaign_id: uuid.UUID) -> Campaign | None:
        stmt = select(Campaign).where(Campaign.id == campaign_id)
        return await self._session.scalar(stmt)

    async def list_for_org(
        self,
        org_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Campaign]:
        stmt = (
            select(Campaign)
            .where(Campaign.org_id == org_id)
            .order_by(Campaign.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_for_engagement(
        self,
        engagement_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Campaign]:
        stmt = (
            select(Campaign)
            .where(Campaign.engagement_id == engagement_id)
            .order_by(Campaign.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_for_org(self, org_id: uuid.UUID) -> int:
        stmt = select(Campaign).where(Campaign.org_id == org_id)
        result = await self._session.execute(stmt)
        return len(list(result.scalars().all()))
