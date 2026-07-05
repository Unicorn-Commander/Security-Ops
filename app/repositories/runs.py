"""RunRepository — data access for :class:`app.models.run.Run`.

Thin async-SQLAlchemy-2.0 data-access layer; repositories NEVER commit (the
caller owns the transaction — the Strix runner commits at run-lifecycle
boundaries). Callers:

* ``app.engine.strix_runner`` drives a run's lifecycle with :meth:`get` (to read
  back the freshest status) and :meth:`set_status` (RUNNING on launch, then a
  terminal COMPLETED / FAILED / STOPPED with timing / cost / usage / report path).
* The run service uses :meth:`get` behind ``GET /runs/{id}``.

Dependency direction (no cycles): repositories -> {models, db}.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.run import Run, RunStatus

# Sentinel distinguishing "argument omitted" (leave the column untouched) from an
# explicit ``None`` (clear the column). This lets the RUNNING transition set only
# started_at / model_profile while a later terminal transition sets ended_at / cost
# / usage / report_path WITHOUT clobbering the started_at recorded at launch.
_UNSET: Any = object()


class RunRepository:
    """Reads and mutates run lifecycle state. Construct per-request with the session."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, run_id: uuid.UUID) -> Run | None:
        """Return the run by primary key, or ``None``. Tenant isolation
        (``org_id`` check) is enforced by the caller (service / routes)."""
        return await self.session.get(Run, run_id)

    async def list_for_engagement(self, engagement_id: uuid.UUID) -> list[Run]:
        """Return all runs for an engagement, newest first.

        Read-only; tenant isolation (``org_id`` check) is the caller's job — the
        report service loads the engagement tenant-checked before calling this.
        Unpaginated by design: a report renders the engagement's full run history."""
        stmt = (
            select(Run)
            .where(Run.engagement_id == engagement_id)
            .order_by(Run.created_at.desc(), Run.id.desc())
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def list_for_org(
        self,
        org_id: uuid.UUID,
        *,
        status: RunStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Run], int]:
        """Return ``(items, total)`` for one org's runs, newest first.

        Org-scoped console list (spec §6): filters on the denormalized ``org_id``
        so a caller only ever sees their own tenant's runs — tenant isolation is
        the WHERE clause itself, not a post-hoc check. An optional ``status``
        narrows the window to one lifecycle state (e.g. RUNNING). ``total`` is the
        unpaginated count of the same (org + status) predicate so the API can
        render a ``Page``. Read-only; never commits.
        """
        predicate = [Run.org_id == org_id]
        if status is not None:
            predicate.append(Run.status == status)
        stmt = (
            select(Run)
            .where(*predicate)
            .order_by(Run.created_at.desc(), Run.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.execute(stmt)).scalars().all())
        total = await self.session.scalar(
            select(func.count()).select_from(Run).where(*predicate)
        )
        return items, int(total or 0)

    async def set_status(
        self,
        run_id: uuid.UUID,
        status: RunStatus,
        *,
        started_at: datetime | None = _UNSET,
        ended_at: datetime | None = _UNSET,
        error: str | None = _UNSET,
        strix_run_id: str | None = _UNSET,
        cost_usd: Decimal | None = _UNSET,
        usage: dict | None = _UNSET,
        model_profile: str | None = _UNSET,
        report_path: str | None = _UNSET,
    ) -> Run:
        """Set a run's ``status`` (and any supplied lifecycle fields) and return it.

        Only fields explicitly passed are written; omitted fields are left as-is
        (see ``_UNSET``), so a terminal transition preserves ``started_at`` from
        the RUNNING transition. Passing an explicit ``None`` clears that column.

        Flushes but does not commit — the caller owns the transaction. Raises
        :class:`sqlalchemy.exc.NoResultFound` if the run does not exist (an
        internal invariant violation: callers create + tenant-check the run first).
        """
        run = await self.session.get(Run, run_id)
        if run is None:
            raise NoResultFound(f"run {run_id} not found")

        run.status = status
        updates = {
            "started_at": started_at,
            "ended_at": ended_at,
            "error": error,
            "strix_run_id": strix_run_id,
            "cost_usd": cost_usd,
            "usage": usage,
            "model_profile": model_profile,
            "report_path": report_path,
        }
        for attr, value in updates.items():
            if value is not _UNSET:
                setattr(run, attr, value)

        await self.session.flush()
        return run
