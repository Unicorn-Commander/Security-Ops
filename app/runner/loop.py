"""The runner poll loop — claim a queued run, execute it, clear the queue row.

Design:

* **Claim** in its own short transaction: ``claim_next`` locks the oldest available
  ``run_queue`` row (``FOR UPDATE SKIP LOCKED``), stamps the claim, and commits —
  releasing the row lock immediately so a slow scan never holds it. N runners can
  share the queue without double-claiming.
* **Execute** outside any lock via :func:`app.engine.strix_runner.execute_run`,
  which opens its own RLS-bound session and runs the full gate-cleared pipeline.
  ``execute_run`` re-checks the emergency stop and refuses a non-PENDING run, so a
  double-claim (should one ever happen) is still safe.
* **Finish** by deleting the queue row (the ``runs`` row is the durable record).

The loop is crash-tolerant: any per-run failure is logged and the loop continues.
It shuts down cleanly on SIGTERM/SIGINT (``docker stop``). Known limitation: a
runner that dies mid-execute leaves its run RUNNING and its queue row claimed
(no auto-requeue in this cut) — surfaced in logs, reconciled by an operator.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import uuid

from app.core.config import settings
from app.db.session import get_sessionmaker
from app.engine.strix_runner import execute_run
from app.repositories.run_queue import claim_next, mark_done

log = logging.getLogger("secops.runner")

_stop = asyncio.Event()


async def _claim_one() -> dict | None:
    """Claim the next queued run in a short committed transaction; snapshot its fields."""
    async with get_sessionmaker()() as session:
        entry = await claim_next(session, worker_id=settings.runner_id)
        if entry is None:
            return None
        claimed = {
            "run_id": entry.run_id,
            "engagement_id": entry.engagement_id,
            "org_id": entry.org_id,
            "scope_mode": entry.scope_mode,
            "diff_base": entry.diff_base,
        }
        await session.commit()  # release the row lock before the long scan
        return claimed


async def _finish(run_id: uuid.UUID) -> None:
    async with get_sessionmaker()() as session:
        await mark_done(session, run_id=run_id)
        await session.commit()


async def _process(claimed: dict) -> None:
    run_id = claimed["run_id"]
    log.info("runner.claimed run=%s", run_id)
    try:
        await execute_run(
            run_id=run_id,
            engagement_id=claimed["engagement_id"],
            org_id=claimed["org_id"],
            actor=f"system:{settings.runner_id}",
            scope_mode=claimed["scope_mode"],
            diff_base=claimed["diff_base"],
        )
    except Exception:  # noqa: BLE001 - one bad run must not stop the loop
        log.exception("runner.execute-failed run=%s", run_id)
    finally:
        try:
            await _finish(run_id)
        except Exception:  # noqa: BLE001
            log.exception("runner.finish-failed run=%s (queue row not cleared)", run_id)


async def run_forever(*, stop: asyncio.Event | None = None) -> None:
    """Claim-and-execute until the stop event is set. Empty queue → poll-interval sleep."""
    ev = stop or _stop
    log.info(
        "secops-runner up id=%s poll=%ss dispatch=%s",
        settings.runner_id,
        settings.runner_poll_seconds,
        settings.run_dispatch_mode,
    )
    while not ev.is_set():
        try:
            claimed = await _claim_one()
        except Exception:  # noqa: BLE001 - a claim hiccup must not kill the loop
            log.exception("runner.claim-failed")
            claimed = None

        if claimed is None:
            try:
                await asyncio.wait_for(ev.wait(), timeout=settings.runner_poll_seconds)
            except asyncio.TimeoutError:
                pass
            continue

        await _process(claimed)

    log.info("secops-runner stopped id=%s", settings.runner_id)


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _stop.set)
        except NotImplementedError:  # pragma: no cover - non-Unix
            pass


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if settings.run_dispatch_mode != "queue":
        log.warning(
            "secops-runner started but SECOPS_RUN_DISPATCH_MODE=%s (not 'queue') — "
            "the API is NOT enqueueing; this runner will idle. Set it to 'queue'.",
            settings.run_dispatch_mode,
        )
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _install_signal_handlers(loop)
    try:
        loop.run_until_complete(run_forever())
    finally:
        loop.close()
