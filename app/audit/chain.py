"""app.audit.chain — the append-only audit hash chain (tamper-evidence).

Pure hashing layer for :class:`app.models.audit.AuditEvent`. It has NO database
or I/O dependency: it turns an event's content plus the previous event's hash into
this event's ``event_hash``, forming a ``prev_hash -> event_hash`` chain that makes
the audit log tamper-evident (SOC2 evidence, spec §4/§5). The persistence side —
finding the current chain head and inserting the row — lives in
:mod:`app.audit.writer`.

The digest is SHA-256 (hex, 64 chars — matching ``AuditEvent.event_hash``'s
``String(64)``) over a canonical JSON serialization (sorted keys, compact
separators) of the salient event fields *and* ``prev_hash``. Because ``prev_hash``
is folded into every digest, altering, reordering, or deleting any historical row
breaks verification from that row forward.

The very first event in a chain (genesis) has ``prev_hash = None``
(:data:`GENESIS_PREV_HASH`); the column is nullable to allow it.
"""

from __future__ import annotations

import datetime as _dt
import enum
import hashlib
import hmac
import json
import uuid
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # annotations only — chain.py never needs the ORM class at runtime
    from app.models.audit import AuditEvent

__all__ = [
    "GENESIS_PREV_HASH",
    "canonical_payload",
    "serialize_payload",
    "compute_event_hash",
    "assign_event_hash",
    "verify_event",
    "verify_chain",
]

# The first event in a chain links to nothing.
GENESIS_PREV_HASH: str | None = None


def _normalize(value: Any) -> Any:
    """Coerce a value into a stable, JSON-serializable, canonical form.

    UUID -> str, Enum -> its ``.value`` (so an
    :class:`~app.models.audit.AuditAction` hashes as ``"RUN_STARTED"`` whether it is
    read back as the enum or its raw value), datetime -> a canonical **UTC** ISO-8601
    string. The datetime is pinned to UTC (a naive value is assumed to be UTC, which
    is always true here — the writer stamps ``datetime.now(timezone.utc)``) so the
    digest is over the same instant whether the DB hands the value back timezone-aware
    (PostgreSQL) or tz-stripped (SQLite under tests); a stored row therefore re-verifies
    after a round-trip. Everything else is returned unchanged and left to the JSON
    encoder (with ``default=str`` as the final safety net).
    """
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, _dt.datetime):
        aware = value if value.tzinfo is not None else value.replace(tzinfo=_dt.timezone.utc)
        return aware.astimezone(_dt.timezone.utc).isoformat()
    if isinstance(value, enum.Enum):
        return value.value
    return value


def canonical_payload(event: "AuditEvent", prev_hash: str | None = None) -> dict[str, Any]:
    """The exact, ordered set of fields folded into an event's hash.

    Includes the row ``id`` and ``created_at`` (so identity and time are bound into
    the chain) and ``prev_hash`` (the chain link). ``event_hash`` itself is
    deliberately excluded — it is the output, not an input.
    """
    return {
        "prev_hash": prev_hash,
        "id": _normalize(getattr(event, "id", None)),
        "action": _normalize(getattr(event, "action", None)),
        "actor_id": getattr(event, "actor_id", None),
        "actor_email": getattr(event, "actor_email", None),
        "org_id": _normalize(getattr(event, "org_id", None)),
        "engagement_id": _normalize(getattr(event, "engagement_id", None)),
        "run_id": _normalize(getattr(event, "run_id", None)),
        "target": getattr(event, "target", None),
        "target_id": _normalize(getattr(event, "target_id", None)),
        "decision": getattr(event, "decision", None),
        "reason": getattr(event, "reason", None),
        "detail": getattr(event, "detail", None),
        "created_at": _normalize(getattr(event, "created_at", None)),
    }


def serialize_payload(payload: dict[str, Any]) -> str:
    """Deterministically serialize a payload dict for hashing.

    ``sort_keys`` makes nested dict ordering irrelevant; list order (e.g. a
    ``violations`` list in ``detail``) is preserved because it is semantically
    meaningful. ``default=str`` is a safety net for any exotic nested value.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def compute_event_hash(event: "AuditEvent", prev_hash: str | None = None) -> str:
    """Return the SHA-256 hex digest binding ``event`` to ``prev_hash``.

    Pure function of the event's content and the previous hash — call it with the
    same inputs anywhere and get the same 64-char digest.
    """
    serialized = serialize_payload(canonical_payload(event, prev_hash))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def assign_event_hash(event: "AuditEvent", prev_hash: str | None = None) -> "AuditEvent":
    """Populate ``event.prev_hash`` and ``event.event_hash`` in place; return event.

    This is how the writer links a freshly-built :class:`AuditEvent` onto the chain:
    ``prev_hash`` is the current head's hash (or :data:`GENESIS_PREV_HASH`), and
    ``event_hash`` is :func:`compute_event_hash` of the event *with* that link.
    """
    event.prev_hash = prev_hash
    event.event_hash = compute_event_hash(event, prev_hash)
    return event


def verify_event(event: "AuditEvent") -> bool:
    """Whether an event's stored ``event_hash`` matches a recomputation.

    Recomputes the digest from the event's content and its own ``prev_hash`` and
    compares in constant time. False means the row (or its ``prev_hash`` link) was
    altered after it was written.
    """
    stored = getattr(event, "event_hash", None)
    if not stored:
        return False
    expected = compute_event_hash(event, getattr(event, "prev_hash", None))
    return hmac.compare_digest(expected, str(stored))


def verify_chain(events: "Iterable[AuditEvent]") -> tuple[bool, int | None]:
    """Verify a sequence of events ordered oldest-first.

    Checks two invariants per row: (1) each event's ``event_hash`` recomputes
    correctly (:func:`verify_event`), and (2) from the second row on, each
    ``prev_hash`` equals the previous row's ``event_hash`` (the links are intact).

    Returns ``(True, None)`` if the whole (sub)chain is sound, else
    ``(False, index)`` where ``index`` is the 0-based position of the first row that
    fails. The first row's ``prev_hash`` is not constrained, so a *slice* of a longer
    chain can be verified on its own.
    """
    prev_hash: str | None = None
    for index, event in enumerate(events):
        if index > 0 and getattr(event, "prev_hash", None) != prev_hash:
            return (False, index)
        if not verify_event(event):
            return (False, index)
        prev_hash = getattr(event, "event_hash", None)
    return (True, None)
