"""Pydantic v2 request/response schemas for Security-Ops.

The API routers import from the submodules directly (e.g.
``from app.schemas.engagement import EngagementRead``); the re-exports here are a
convenience for ``from app.schemas import EngagementRead`` and to give the package
a single public surface.
"""

from app.schemas.attack_path import (
    AttackPathEdge,
    AttackPathGraph,
    AttackPathNode,
    AttackPathSummary,
)
from app.schemas.common import Page
from app.schemas.engagement import (
    EngagementCreate,
    EngagementRead,
    EngagementScope,
    RulesOfEngagement,
    ScopeCheckRequest,
    ScopeDecisionRead,
    ScopeRule,
    ScopeSelection,
)
from app.schemas.finding import FindingRead
from app.schemas.run import RunCreate, RunRead
from app.schemas.target import AttestationRequest, TargetCreate, TargetRead

__all__ = [
    # attack-path
    "AttackPathEdge",
    "AttackPathGraph",
    "AttackPathNode",
    "AttackPathSummary",
    # common
    "Page",
    # engagement
    "EngagementCreate",
    "EngagementRead",
    "EngagementScope",
    "RulesOfEngagement",
    "ScopeCheckRequest",
    "ScopeDecisionRead",
    "ScopeRule",
    "ScopeSelection",
    # finding
    "FindingRead",
    # run
    "RunCreate",
    "RunRead",
    # target
    "AttestationRequest",
    "TargetCreate",
    "TargetRead",
]
