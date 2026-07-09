"""Attack-path / exposure-graph route (spec §6 — console read surface).

Endpoint (under ``/api/v1``; requires SSO + the ``security-ops`` entitlement,
enforced transitively via ``CurrentOrg``):

    GET    /engagements/{engagement_id}/attack-path -> AttackPathGraph

Returns a layered attack-path graph *derived* from the engagement's stored
findings (engagement root → affected host → finding leaf), with severity rolled
up per host and a small summary. It is purely additive and READ-ONLY: it loads the
engagement's findings and hands them to the pure
:func:`app.services.attack_path.build_attack_path_graph`, mutating nothing (no
commit) and requiring no Strix step-log plumbing.

Tenant isolation is identical to the sibling engagement routes: ``_load_engagement``
compares ``engagement.org_id`` against ``CurrentOrg`` (a missing or cross-org
engagement is a 404), and resolving ``CurrentOrg`` also arms Postgres RLS for the
request — so the findings query is org-filtered by the database too.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from app.api.deps import CurrentOrg, DbSession
from app.core.errors import NotFoundError
from app.repositories.engagements import EngagementRepository
from app.repositories.findings import FindingRepository
from app.schemas.attack_path import AttackPathGraph
from app.services.attack_path import build_attack_path_graph

router = APIRouter(tags=["attack-path"])


async def _load_engagement(session, engagement_id: uuid.UUID, org):
    """Fetch an engagement, enforcing tenant isolation (cross-org == 404)."""
    engagement = await EngagementRepository(session).get(engagement_id)
    if engagement is None or engagement.org_id != org.id:
        raise NotFoundError("Engagement not found")
    return engagement


@router.get(
    "/engagements/{engagement_id}/attack-path",
    response_model=AttackPathGraph,
)
async def engagement_attack_path_route(
    engagement_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
) -> AttackPathGraph:
    """Derive the engagement's attack-path/exposure graph from its findings.

    Tenant-checked via ``_load_engagement`` (cross-org == 404). Loads every finding
    for the engagement (the denormalized ``engagement_id`` makes this a single-table
    read) and returns the pure builder's graph. Read-only — no rows are mutated.
    """
    engagement = await _load_engagement(session, engagement_id, org)
    findings, _total = await FindingRepository(session).list_for_engagement(
        engagement.id
    )
    return build_attack_path_graph(engagement, findings)
