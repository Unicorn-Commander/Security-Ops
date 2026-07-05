"""app.repositories — the data-access layer for Security-Ops.

One repository per aggregate, each constructed per-request with the active
``AsyncSession``. Repositories are thin async-SQLAlchemy-2.0 query/mutation
helpers that NEVER commit — the caller (service / route / the authorization
gate / the Strix runner) owns the transaction (see
``app.db.session.get_session``).

Callers import the concrete class directly (e.g.
``from app.repositories.engagements import EngagementRepository``); the classes
are also re-exported here for convenience.

Dependency direction (no cycles): repositories -> {models, db}. This layer never
imports authz / services / api.
"""

from __future__ import annotations

from app.repositories.engagements import EngagementRepository
from app.repositories.findings import FindingRepository
from app.repositories.runs import RunRepository
from app.repositories.targets import TargetRepository

__all__ = [
    "EngagementRepository",
    "TargetRepository",
    "FindingRepository",
    "RunRepository",
]
