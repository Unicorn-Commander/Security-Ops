"""Console dashboard-overview route (spec §6).

Endpoint (under ``/api/v1``; requires SSO + the ``security-ops`` entitlement,
enforced transitively via ``CurrentOrg``):

    GET    /overview -> OverviewRead

Returns the org-scoped summary the new console's landing page renders:
engagement / target / run / finding totals broken down by lifecycle state, plus
the headline counts (active engagements, attested targets, running runs, open
findings). Tenant isolation is structural: the route passes ``org.id`` (from
``CurrentOrg``) to ``OverviewRepository``, whose every ``GROUP BY`` count filters
on that ``org_id`` — a caller can only ever see their own tenant's numbers. The
route is READ-ONLY: it issues four grouped-count queries and mutates nothing (no
commit).
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import CurrentOrg, DbSession
from app.repositories.overview import OverviewRepository
from app.schemas.overview import OverviewRead

router = APIRouter(tags=["overview"])


@router.get("/overview", response_model=OverviewRead)
async def overview_route(
    session: DbSession,
    org: CurrentOrg,
) -> OverviewRead:
    summary = await OverviewRepository(session).summary(org.id)
    return OverviewRead.model_validate(summary)
