"""Console dashboard-overview schema (spec §6).

Typed contract for ``GET /overview`` — the org-scoped summary the new console's
landing page renders. Built directly from the ``{...}`` maps
``app.repositories.overview.OverviewRepository.summary`` returns
(``OverviewRead.model_validate(summary_dict)``), so the field names here mirror
that repository's output 1:1.

Every count is tenant-scoped by construction — the repository filters each
``GROUP BY`` on ``org_id`` — so this model never carries another tenant's data.
The ``by_status`` / ``by_severity`` maps are keyed by the enum ``.value`` string
actually stored in the DB (e.g. ``{"ACTIVE": 3, "DRAFT": 1}``); absent states are
simply omitted rather than zero-filled.
"""

from __future__ import annotations

from pydantic import BaseModel


class EngagementsOverview(BaseModel):
    total: int
    by_status: dict[str, int]
    active: int


class TargetsOverview(BaseModel):
    total: int
    attested: int
    by_status: dict[str, int]


class RunsOverview(BaseModel):
    total: int
    by_status: dict[str, int]
    running: int


class FindingsOverview(BaseModel):
    total: int
    by_severity: dict[str, int]
    # Findings still needing action: status NEW or VERIFIED.
    open: int


class OverviewRead(BaseModel):
    """Org-scoped dashboard summary for the console landing page."""

    engagements: EngagementsOverview
    targets: TargetsOverview
    runs: RunsOverview
    findings: FindingsOverview
