"""CampaignRun repository."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import CampaignRun


class CampaignRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, run_id: uuid.UUID) -> CampaignRun | None:
        stmt = select(CampaignRun).where(CampaignRun.id == run_id)
        return await self._session.scalar(stmt)

    async def list_for_campaign(
        self,
        campaign_id: uuid.UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CampaignRun]:
        stmt = (
            select(CampaignRun)
            .where(CampaignRun.campaign_id == campaign_id)
            .order_by(CampaignRun.created_at.asc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
