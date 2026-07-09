"""app/engine/brigade_handoff.py — Brigade findings hand-off (Security-Ops Phase 2, spec §8).

"Security-Ops *finds*; Brigade *fixes*." This module turns a confirmed :class:`Finding`
into a Brigade agent task (triage -> ticket / draft remediation PR / exec summary) and
records the hand-off on the finding (``handoff_ref`` + ``status=HANDED_OFF``) with an
append-only ``FINDING_HANDOFF`` audit event.

Stub boundary (honest, not a TODO): the payload-building + persistence + audit paths are
fully implemented and exercised. Only the *network submission* is gated on an injected
Brigade intake endpoint. Until that endpoint/credential is provisioned,
``BrigadeHandoffClient.submit`` raises :class:`HandoffNotConfigured` (HTTP 501) — which is
exactly why the API's ``POST /findings/{id}/handoff`` returns 501 in this phase. Wiring
Brigade is then a one-line config change (``settings.brigade_base_url`` /
``brigade_api_key``), no code change to this orchestration.

Dependency direction (no cycles): engine -> {core.config, core.errors, models,
audit.writer, repositories.findings}. Nothing imports engine.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.errors import AppError, ConflictError, ValidationAppError
from app.models.audit import AuditAction
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.audit.writer import record_event
from app.repositories.findings import FindingRepository

if TYPE_CHECKING:  # typing only; avoids runtime import weight / cycles
    from app.auth.middleware import AuthUser
    from app.models.engagement import Engagement
    from app.models.run import Run

log = logging.getLogger(__name__)

# Default Brigade persona that receives security remediation work (spec §8).
BRIGADE_HANDOFF_AGENT = "security-remediation"

# Only NEW or VERIFIED findings may be handed off; terminal/false-positive states cannot.
_HANDOFFABLE: frozenset[FindingStatus] = frozenset({FindingStatus.NEW, FindingStatus.VERIFIED})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class HandoffNotConfigured(AppError):
    """Brigade intake endpoint is not configured — the Phase-2 stub boundary (HTTP 501)."""

    def __init__(
        self,
        message: str = "Brigade hand-off endpoint is not configured (Phase 2)",
        *,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message, code="brigade_handoff_not_configured", status_code=501, detail=detail
        )


class HandoffError(AppError):
    """Brigade rejected or failed to accept the hand-off (HTTP 502)."""

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message, code="brigade_handoff_failed", status_code=502, detail=detail)


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------


@dataclass
class BrigadeHandoffPayload:
    """The agent-task request Brigade receives for one confirmed finding."""

    finding_id: str
    title: str
    severity: str
    org_id: str | None
    engagement_id: str | None
    run_id: str | None
    cwe: str | None
    endpoint: str | None
    payload: str | None
    poc: str | None
    evidence: dict[str, Any]
    remediation_request: str
    agent: str = BRIGADE_HANDOFF_AGENT
    source: str = "security-ops"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "agent": self.agent,
            "kind": "security_finding_remediation",
            "created_at": self.created_at,
            "finding": {
                "id": self.finding_id,
                "title": self.title,
                "severity": self.severity,
                "cwe": self.cwe,
                "endpoint": self.endpoint,
                "payload": self.payload,
                "poc": self.poc,
                "evidence": self.evidence,
            },
            "context": {
                "org_id": self.org_id,
                "engagement_id": self.engagement_id,
                "run_id": self.run_id,
            },
            "request": self.remediation_request,
        }


def _severity_value(finding: Finding) -> str:
    sev = getattr(finding, "severity", None)
    return sev.value if isinstance(sev, FindingSeverity) else str(sev) if sev is not None else "unknown"


def _remediation_request(finding: Finding, severity: str) -> str:
    where = getattr(finding, "endpoint", None) or "the affected asset"
    return (
        f"A {severity.upper()} security finding — '{getattr(finding, 'title', 'finding')}' — "
        f"was confirmed against {where} by Security-Ops. Please triage, open a tracking "
        f"ticket, draft a remediation PR (with the fix and a regression test), and write a "
        f"short exec summary. Do NOT re-run offensive tooling; use the attached evidence/PoC."
    )


def build_handoff_payload(
    finding: Finding,
    *,
    engagement: "Engagement | None" = None,
    run: "Run | None" = None,
    agent: str = BRIGADE_HANDOFF_AGENT,
) -> BrigadeHandoffPayload:
    """Build the Brigade agent-task payload from a finding (pure; no I/O)."""
    severity = _severity_value(finding)
    engagement_id = getattr(finding, "engagement_id", None) or getattr(engagement, "id", None)
    run_id = getattr(finding, "run_id", None) or getattr(run, "id", None)
    return BrigadeHandoffPayload(
        finding_id=str(getattr(finding, "id", "")),
        title=str(getattr(finding, "title", "Untitled finding")),
        severity=severity,
        org_id=_opt_str(getattr(finding, "org_id", None)),
        engagement_id=_opt_str(engagement_id),
        run_id=_opt_str(run_id),
        cwe=getattr(finding, "cwe", None),
        endpoint=getattr(finding, "endpoint", None),
        payload=getattr(finding, "payload", None),
        poc=getattr(finding, "poc", None),
        evidence=getattr(finding, "evidence", None) or {},
        remediation_request=_remediation_request(finding, severity),
        agent=agent,
    )


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _actor_label(actor: "AuthUser | str") -> str:
    for attr in ("email", "id", "sub", "username"):
        value = getattr(actor, attr, None)
        if value:
            return str(value)
    return str(actor)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class BrigadeHandoffClient:
    """Submits hand-off payloads to Brigade's agent-task intake.

    ``base_url``/``api_key`` are injected (default: pulled from settings if present). With
    no ``base_url`` the client is *unconfigured* and ``submit`` raises
    :class:`HandoffNotConfigured` — the deliberate Phase-2 boundary.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        agent: str = BRIGADE_HANDOFF_AGENT,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/") or None
        self.api_key = api_key
        self.agent = agent
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return self.base_url is not None

    async def submit(self, payload: BrigadeHandoffPayload | dict[str, Any]) -> dict[str, Any]:
        """POST the payload to Brigade; return the parsed response dict.

        Raises :class:`HandoffNotConfigured` if no endpoint is wired, or
        :class:`HandoffError` on any transport/HTTP failure.
        """
        if not self.base_url:
            raise HandoffNotConfigured()

        body = payload.to_dict() if isinstance(payload, BrigadeHandoffPayload) else dict(payload)
        url = f"{self.base_url}/api/v1/agent-tasks"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=body, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            raise HandoffError(
                f"Brigade rejected hand-off (HTTP {exc.response.status_code})",
                detail={"status": exc.response.status_code, "body": exc.response.text[:2000]},
            ) from exc
        except httpx.HTTPError as exc:
            raise HandoffError(f"Brigade hand-off transport error: {exc}") from exc

        return data if isinstance(data, dict) else {"result": data}


def default_client(config: Settings | None = None) -> BrigadeHandoffClient:
    """Build the default client from settings (forward-compatible: reads optional
    ``brigade_base_url`` / ``brigade_api_key`` if/when config exposes them; otherwise
    returns an unconfigured client that surfaces the 501 stub boundary)."""
    cfg = config or settings
    return BrigadeHandoffClient(
        base_url=getattr(cfg, "brigade_base_url", None),
        api_key=getattr(cfg, "brigade_api_key", None),
    )


def _extract_ref(response: dict[str, Any]) -> str | None:
    for key in ("id", "task_id", "ticket_id", "ref", "handoff_ref", "url"):
        value = response.get(key)
        if value:
            return str(value)
    return None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def handoff_finding(
    session: AsyncSession,
    *,
    finding: Finding,
    actor: "AuthUser | str",
    engagement: "Engagement | None" = None,
    run: "Run | None" = None,
    client: BrigadeHandoffClient | None = None,
) -> Finding:
    """Hand a confirmed finding to Brigade and record it.

    Steps: guard eligibility -> build payload -> submit to Brigade -> set
    ``finding.handoff_ref`` + ``status=HANDED_OFF`` -> append ``FINDING_HANDOFF`` audit.
    Follows the suite convention that request-path helpers do NOT commit — the caller
    (service/route) owns the transaction — so this flushes but leaves the commit to them.

    Raises :class:`ConflictError` (already handed off / remediated),
    :class:`ValidationAppError` (false positive), :class:`HandoffNotConfigured` (no
    Brigade endpoint — surfaces as 501), or :class:`HandoffError` (submission failed).
    """
    status = getattr(finding, "status", None)
    if status in (FindingStatus.HANDED_OFF, FindingStatus.REMEDIATED):
        raise ConflictError(
            f"finding {finding.id} already handed off "
            f"(status={getattr(status, 'value', status)})"
        )
    if status == FindingStatus.FALSE_POSITIVE:
        raise ValidationAppError("cannot hand off a finding marked FALSE_POSITIVE")
    if status not in _HANDOFFABLE:
        raise ValidationAppError(
            f"finding {finding.id} is not eligible for hand-off "
            f"(status={getattr(status, 'value', status)})"
        )

    payload = build_handoff_payload(finding, engagement=engagement, run=run)
    client = client or default_client()

    response = await client.submit(payload)
    ref = _extract_ref(response)

    finding.handoff_ref = ref
    finding.status = FindingStatus.HANDED_OFF
    finding.closure_reason = "handed off to Brigade"
    finding.closed_by = _actor_label(actor)
    finding.closed_at = datetime.now(timezone.utc)
    await session.flush()
    await session.refresh(finding)

    await record_event(
        session,
        action=AuditAction.FINDING_HANDOFF,
        actor=actor,
        org_id=getattr(finding, "org_id", None),
        engagement_id=getattr(finding, "engagement_id", None),
        run_id=getattr(finding, "run_id", None),
        target=getattr(finding, "endpoint", None),
        decision="handoff",
        detail={
            "handoff_ref": ref,
            "severity": _severity_value(finding),
            "agent": client.agent,
            "title": getattr(finding, "title", None),
        },
    )
    log.info("brigade.handoff.ok finding=%s ref=%s agent=%s", finding.id, ref, client.agent)
    return finding
