"""app.audit — the suite-wide, append-only, hash-chained audit log.

The single source of truth for immutable audit evidence (spec §4/§5). Append rows
through :func:`app.audit.writer.record_event`; the tamper-evident ``prev_hash ->
event_hash`` chaining lives in :mod:`app.audit.chain`. Consumers may import from
this package directly or from the submodules (existing call sites use
``from app.audit.writer import record_event``).
"""

from __future__ import annotations

from app.audit.chain import (
    GENESIS_PREV_HASH,
    assign_event_hash,
    compute_event_hash,
    verify_chain,
    verify_event,
)
from app.audit.writer import record_event

__all__ = [
    "record_event",
    "compute_event_hash",
    "assign_event_hash",
    "verify_event",
    "verify_chain",
    "GENESIS_PREV_HASH",
]
