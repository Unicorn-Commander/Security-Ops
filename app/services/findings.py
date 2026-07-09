"""Finding triage service (spec §6) — the operator-settable status transition.

"Security-Ops finds; Brigade fixes." A human (console) or an agent (MCP) triages a
finding by setting its status: confirm it (``VERIFIED``), dismiss it
(``FALSE_POSITIVE``), close it out (``REMEDIATED``), or reopen it (``NEW``). This is
the counterpart to the Brigade hand-off — the hand-off owns the ``HANDED_OFF``
transition, and this path deliberately refuses to set it.

Every real change appends exactly one immutable ``FINDING_TRIAGED`` audit row via
:func:`app.audit.writer.record_event`, so the tamper-evident chain records who
moved a finding to which state and why — the same SOC2 evidence the hand-off
writes.

Transaction contract (suite convention — request-path helpers do NOT commit): this
flushes (through ``record_event``) but leaves the commit to the caller (route /
MCP impl), exactly like ``app.engine.brigade_handoff.handoff_finding``.

Dependency direction (no cycles): services -> {core.errors, audit.writer,
models}. Nothing there imports services.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.writer import record_event
from app.core.errors import ValidationAppError
from app.models.audit import AuditAction
from app.models.finding import Finding, FindingStatus

if TYPE_CHECKING:  # typing only — no runtime coupling / cycle
    from app.auth.sso import AuthUser

logger = logging.getLogger("secops.services.findings")

# Statuses an operator may set directly via triage. HANDED_OFF is deliberately
# excluded — it is owned by the Brigade hand-off flow (app.engine.brigade_handoff).
_OPERATOR_SETTABLE: frozenset[FindingStatus] = frozenset(
    {
        FindingStatus.NEW,  # reopen
        FindingStatus.VERIFIED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.REMEDIATED,
    }
)
_CLOSING_STATUSES: frozenset[FindingStatus] = frozenset(
    {FindingStatus.FALSE_POSITIVE, FindingStatus.REMEDIATED, FindingStatus.HANDED_OFF}
)


def _status_value(status: object) -> object:
    return getattr(status, "value", status)


def _actor_label(actor: "AuthUser | str") -> str:
    for attr in ("email", "id", "sub", "username"):
        value = getattr(actor, attr, None)
        if value:
            return str(value)
    return str(actor)


async def set_finding_status(
    session: AsyncSession,
    *,
    finding: Finding,
    new_status: FindingStatus,
    actor: "AuthUser | str",
    closure_reason: str | None = None,
) -> Finding:
    """Set a finding's status via operator triage and record it (audited).

    Rules:

    * ``new_status`` must be operator-settable (``NEW`` / ``VERIFIED`` /
      ``FALSE_POSITIVE`` / ``REMEDIATED``). Setting ``HANDED_OFF`` through this path
      is refused with a :class:`~app.core.errors.ValidationAppError` (HTTP 422) —
      that transition belongs to the Brigade hand-off flow.
    * Idempotent: setting the current status returns the finding unchanged and
      writes NO audit row.
    * On a real change: flip the status and append exactly one ``FINDING_TRIAGED``
      audit row (org/engagement/run scope + ``detail={"from", "to"}``).

    Follows the suite convention that request-path helpers do NOT commit — the
    caller (route / MCP impl) owns the transaction; this flushes via
    ``record_event`` and leaves the commit to them.

    Raises :class:`ValidationAppError` (HTTP 422) when ``new_status`` is not
    operator-settable.
    """
    if new_status not in _OPERATOR_SETTABLE:
        raise ValidationAppError(
            f"status {_status_value(new_status)!r} is not operator-settable via triage",
            detail={
                "status": _status_value(new_status),
                "allowed": [s.value for s in FindingStatus if s in _OPERATOR_SETTABLE],
            },
        )

    old_status = finding.status
    # Idempotent: no change → no audit row, nothing to persist.
    if old_status == new_status:
        return finding

    old_value = _status_value(old_status)
    new_value = _status_value(new_status)
    finding.status = new_status
    if new_status in _CLOSING_STATUSES:
        finding.closure_reason = (closure_reason or "").strip() or None
        finding.closed_by = _actor_label(actor)
        finding.closed_at = datetime.now(timezone.utc)
    else:
        finding.closure_reason = None
        finding.closed_by = None
        finding.closed_at = None
    await session.flush()
    await session.refresh(finding)

    await record_event(
        session,
        action=AuditAction.FINDING_TRIAGED,
        actor=actor,
        org_id=getattr(finding, "org_id", None),
        engagement_id=getattr(finding, "engagement_id", None),
        run_id=getattr(finding, "run_id", None),
        target=getattr(finding, "endpoint", None),
        decision="triaged",
        reason=finding.closure_reason or f"finding marked {new_value}",
        detail={"from": old_value, "to": new_value},
    )
    logger.info(
        "finding.triaged finding=%s from=%s to=%s", finding.id, old_value, new_value
    )
    return finding
