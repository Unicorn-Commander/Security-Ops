"""Run lifecycle service — the GATE-ENFORCED path (spec §4/§6/§7).

This module owns the single most security-critical operation in Security-Ops:
:func:`start_run`. It is the **only** caller of the target-authorization gate
(``app.authz.gate.enforce_scope``). Before a run row is created — and before the
Strix engine is launched — EVERY concrete target of the run must clear the gate.
If the gate refuses any target, an :class:`~app.authz.errors.AuthorizationDenied`
(HTTP 403) propagates unchanged and **no run is created**, so an unauthorized
target can never reach the engine. The engine is never trusted to self-limit
(the runner's ``--instruction-file`` scoping is belt-and-suspenders only).

Transaction model (suite convention — "services own their transactions"):

* ``start_run`` gates every target, then creates a ``PENDING`` run + a
  ``RUN_STARTED`` audit row and commits, then hands the run to the detached Strix
  worker (``app.engine.strix_runner.launch_run_background``), which owns its own
  session for the (30+ min) scan.
* On a gate denial, the append-only ``SCOPE_CHECK_*`` rows the gate just wrote
  are committed *before* the 403 propagates — ``app.db.session.get_session`` rolls
  back on exception, so without this the immutable deny evidence would be lost
  (mirrors the entitlement-gate pattern). A commit failure never masks the denial.
* ``stop_run`` signals the live subprocess (best-effort, process control only) and
  flips the run to ``STOPPED`` with a ``RUN_STOPPED`` audit row; it is idempotent
  for an already-terminal run (never clobbers a COMPLETED/FAILED result).

Dependency direction (no cycles): services -> {authz.gate, authz.errors,
audit.writer, engine.strix_runner, repositories, models}. Nothing there imports
services.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.writer import record_event
from app.authz.errors import AuthorizationDenied
from app.authz.gate import enforce_scope
from app.core.errors import ValidationAppError
from app.engine.strix_runner import launch_run_background, stop_run_process
from app.models.audit import AuditAction
from app.models.run import Run, RunStatus
from app.repositories.runs import RunRepository
from app.schemas.engagement import DEFAULT_MODEL_PROFILE

if TYPE_CHECKING:  # typing only — no runtime coupling / cycle
    from app.auth.sso import AuthUser
    from app.models.engagement import Engagement
    from app.schemas.run import RunCreate

logger = logging.getLogger("secops.services.runs")

# Run states that mean "already ended" — stop is a no-op and must not clobber them.
_TERMINAL_RUN_STATUSES: frozenset[RunStatus] = frozenset(
    {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.STOPPED, RunStatus.DENIED}
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _enum_value(value: object) -> object:
    return getattr(value, "value", value)


async def get_run(session: AsyncSession, run_id: uuid.UUID) -> Run | None:
    """Return the run by id, or ``None``. Tenant isolation (the ``org_id`` check)
    is the caller's responsibility — the route compares ``run.org_id`` to the
    current org and renders a cross-org hit as 404."""
    return await RunRepository(session).get(run_id)


async def start_run(
    session: AsyncSession,
    *,
    engagement: "Engagement",
    actor: "AuthUser",
    data: "RunCreate",
) -> Run:
    """Start a scan run — THE authorization chokepoint (spec §4).

    Enforces the gate for EVERY target in ``data.targets`` *before* creating a run
    row or launching anything: each target is run through
    :func:`app.authz.gate.enforce_scope`, which validates engagement lifecycle
    (ACTIVE / unexpired / inside its time window / not emergency-stopped / global
    kill-switch off) + scope membership + a valid attestation, appends exactly one
    immutable audit row, and raises the matching
    :class:`~app.authz.errors.AuthorizationDenied` (HTTP 403) on any refusal.

    A pre-generated ``run_id`` correlates the gate's ``SCOPE_CHECK_*`` audit rows
    with the run they authorize (and, on denial, with the attempt that was
    refused — audit rows carry no FK, so an orphan correlation id is safe). Only
    after *every* target is allowed is the ``PENDING`` run persisted, a
    ``RUN_STARTED`` audit row appended, the transaction committed, and the run
    handed to the detached Strix worker.

    On denial the gate's audit rows are committed before the 403 propagates so the
    deny evidence survives ``get_session``'s rollback; no run is ever created.
    Returns the committed ``PENDING`` run.
    """
    targets = [t for t in (data.targets or []) if isinstance(t, str) and t.strip()]
    # Defense-in-depth: the schema already guarantees >=1 non-empty target, but a
    # run that gated nothing must never be created (that would be an ungated run).
    if not targets:
        raise ValidationAppError(
            "a run requires at least one target",
            detail={"field": "targets"},
        )

    # Correlate every gate decision (and the run) under one id.
    run_id = uuid.uuid4()

    # -- THE GATE: authorize EVERY target before creating a run / launching. -----
    try:
        for target in targets:
            await enforce_scope(
                session,
                engagement.id,
                target,
                actor=actor,
                run_id=run_id,
            )
    except AuthorizationDenied:
        # Persist the append-only SCOPE_CHECK_* rows the gate wrote, then let the
        # 403 propagate unchanged. No run row exists — the denial created nothing.
        await _persist_gate_audit(session)
        raise

    # -- All targets authorized -> create the PENDING run. -----------------------
    model_profile = (
        data.model_profile
        or getattr(engagement, "model_profile", None)
        or DEFAULT_MODEL_PROFILE
    )
    run = Run(
        id=run_id,
        engagement_id=engagement.id,
        org_id=engagement.org_id,
        mode=data.mode,
        model_profile=model_profile,
        targets=targets,
        status=RunStatus.PENDING,
    )
    session.add(run)
    await session.flush()

    await record_event(
        session,
        action=AuditAction.RUN_STARTED,
        actor=actor,
        org_id=run.org_id,
        engagement_id=engagement.id,
        run_id=run.id,
        decision="started",
        reason=f"run started over {len(targets)} authorized target(s)",
        detail={
            "mode": _enum_value(data.mode),
            "model_profile": model_profile,
            "targets": targets,
            "target_count": len(targets),
        },
    )
    await session.commit()

    # -- Phase 2: hand the gate-cleared PENDING run to the Strix subprocess. ------
    # Detached worker owns its own session (the request session is gone by the time
    # a 30+ min scan finishes). A launch hiccup must not fail run creation — the run
    # stays PENDING and can be executed later.
    _launch_worker(run_id=run.id, engagement_id=engagement.id, actor=actor)
    return run


async def stop_run(
    session: AsyncSession,
    *,
    run: Run,
    actor: "AuthUser",
) -> Run:
    """Stop a run: signal the live Strix subprocess and flip it to ``STOPPED``.

    Idempotent — if the run is already terminal (COMPLETED / FAILED / STOPPED /
    DENIED) it is returned unchanged (no re-audit, no clobber). Otherwise the
    subprocess is signalled (best-effort; process control only — the DB flip is
    authoritative), the status is set to ``STOPPED`` with ``ended_at``, and a
    ``RUN_STOPPED`` audit row is appended before commit.
    """
    if run.status in _TERMINAL_RUN_STATUSES:
        return run

    previous_status = run.status

    # Process control only — the DB status flip below is the authoritative stop.
    try:
        await stop_run_process(run.id)
    except Exception:  # noqa: BLE001 - a signalling hiccup must not block the stop
        logger.warning(
            "stop_run: error signalling strix subprocess for run=%s",
            run.id,
            exc_info=True,
        )

    stopped = await RunRepository(session).set_status(
        run.id,
        RunStatus.STOPPED,
        ended_at=_utcnow(),
    )
    await record_event(
        session,
        action=AuditAction.RUN_STOPPED,
        actor=actor,
        org_id=stopped.org_id,
        engagement_id=stopped.engagement_id,
        run_id=stopped.id,
        decision="stopped",
        reason="run stopped by operator",
        detail={"previous_status": _enum_value(previous_status)},
    )
    await session.commit()
    return stopped


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------
async def _persist_gate_audit(session: AsyncSession) -> None:
    """Commit the gate's append-only ``SCOPE_CHECK_*`` rows before a denial 403.

    ``get_session`` rolls back on exception, so without an explicit commit the
    immutable deny evidence the gate just wrote would be discarded. A commit
    failure must never mask the security denial (the caller re-raises regardless),
    so this swallows and logs its own errors.
    """
    try:
        await session.commit()
    except Exception:  # noqa: BLE001 - never let audit persistence mask the denial
        logger.warning(
            "start_run: failed to persist gate audit rows before denial",
            exc_info=True,
        )
        try:
            await session.rollback()
        except Exception:  # noqa: BLE001
            pass


def _launch_worker(
    *,
    run_id: uuid.UUID,
    engagement_id: uuid.UUID,
    actor: "AuthUser",
) -> None:
    """Schedule the detached Strix worker; never raise into the request path."""
    try:
        launch_run_background(run_id=run_id, engagement_id=engagement_id, actor=actor)
    except RuntimeError as exc:
        # No running event loop (e.g. invoked from a sync management context). The
        # run is already committed PENDING and can be executed later.
        logger.warning(
            "start_run: could not launch background worker for run=%s: %s",
            run_id,
            exc,
        )
    except Exception:  # noqa: BLE001 - launch is best-effort; run creation stands
        logger.exception(
            "start_run: unexpected error launching background worker for run=%s",
            run_id,
        )


__all__ = ["get_run", "start_run", "stop_run"]
