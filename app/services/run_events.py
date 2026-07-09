"""Run-event emitter — the durable, fire-and-forget writer for the live trace.

The runner calls these at lifecycle points (dispatched / running / spawned /
reasoning / finding / verify / terminal). Each emit opens its OWN short,
org-bound session and commits, so a trace line is durable and visible to the SSE
reader immediately — decoupled from the runner's long-lived main-session
transaction (which commits only at lifecycle boundaries and may roll back).

Everything here is **best-effort and non-fatal**: a trace is an operator
convenience, never load-bearing. Any error is swallowed + logged so a DB hiccup
while writing a trace line can NEVER fail or stall a scan. Mirrors the resilient
fresh-session idiom of ``StrixRunner._run_externally_stopped``.

Dependency direction (no cycles): services -> {repositories, db, models}.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Iterable

from app.db.session import get_sessionmaker
from app.models.run_event import RunEventType
from app.repositories.run_events import RunEventRepository

logger = logging.getLogger("secops.services.run_events")


def _type_value(event_type: "RunEventType | str") -> str:
    return getattr(event_type, "value", str(event_type))


async def emit_run_event(
    *,
    run_id: uuid.UUID,
    org_id: uuid.UUID,
    event_type: "RunEventType | str",
    message: str | None = None,
    data: dict[str, Any] | None = None,
) -> int | None:
    """Append one trace event in its own committed, org-bound session.

    Returns the assigned ``seq`` (for tests / cursoring), or ``None`` if the write
    failed — a failure is logged and swallowed so it never disturbs the caller.
    """
    return await emit_run_events(
        run_id=run_id, org_id=org_id, events=[(event_type, message, data)]
    )


async def emit_run_events(
    *,
    run_id: uuid.UUID,
    org_id: uuid.UUID,
    events: Iterable[tuple["RunEventType | str", str | None, dict[str, Any] | None]],
) -> int | None:
    """Append a BATCH of trace events in ONE committed, org-bound session.

    Used by the reasoning tail so a burst of live output costs one commit per
    poll-tick, not one per line. Returns the last assigned ``seq`` (or ``None`` on
    failure / empty batch). Best-effort: never raises.
    """
    batch = list(events)
    if not batch:
        return None

    from app.db.rls import clear_org_context, set_org_context  # lazy: avoid cycle

    last_seq: int | None = None
    try:
        async with get_sessionmaker()() as session:
            await set_org_context(session, org_id)
            repo = RunEventRepository(session)
            # Assign contiguous seqs for the whole batch off a single read.
            seq = await repo.latest_seq(run_id)
            for event_type, message, data in batch:
                seq += 1
                await repo.append(
                    run_id=run_id,
                    org_id=org_id,
                    event_type=_type_value(event_type),
                    message=message,
                    data=data,
                    seq=seq,
                )
                last_seq = seq
            await clear_org_context(session)
            await session.commit()
        return last_seq
    except Exception:  # noqa: BLE001 - a trace write must never disturb the scan
        logger.warning(
            "emit_run_events: failed to write %d trace event(s) for run=%s",
            len(batch),
            run_id,
            exc_info=True,
        )
        return None


__all__ = ["emit_run_event", "emit_run_events", "RunEventType"]
