"""The Security-Ops MCP server — full agent parity with the human console.

Every operation a person can perform through the HTTP API is exposed here as an
MCP tool. Each tool runs inside :func:`app.mcp.auth.mcp_scope` (authenticate →
entitle → tenant-scope under RLS) and then delegates to the **same service layer**
the REST routes use — it never re-implements business logic and never bypasses a
guardrail. In particular the destructive tools reach the identical server-side
checks:

* ``runs_start`` → :func:`app.services.runs.start_run` → the authorization gate
  (:func:`app.authz.gate.enforce_scope`) for EVERY target, so a scan against a
  target that is out-of-scope or not covered by a valid attestation is refused for
  an agent exactly as it is for a human;
* ``engagements_activate`` fails closed unless every in-scope rule is attested;
* ``targets_attest`` runs the same live ownership-proof enforcement;
* ``engagements_stop`` engages the emergency stop.

Tool inputs reuse the REST Pydantic request schemas (``EngagementCreate``,
``TargetCreate``, ``AttestationRequest``, ``RunCreate``) and outputs are the REST
read schemas' JSON shapes, so an agent and the console speak the same contract.

Each tool is a thin wrapper over a module-level ``_*_impl`` coroutine that takes a
resolved :class:`~app.mcp.auth.McpContext`; the impls are the unit-tested seam
(they exercise the real gate against an injected session).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from app.auth.sso import UserRole
from app.authz.attestation import attest_target
from app.authz.cloud_proof import cloud_instructions
from app.authz.gate import check_scope
from app.authz.proof import proof_instructions
from app.core.errors import NotFoundError, ValidationAppError
from app.engine.brigade_handoff import handoff_finding
from app.mcp.auth import BearerTokenMiddleware, McpContext, mcp_scope
from app.mcp.http_guard import McpHttpGuard
from app.models.finding import FindingSeverity, FindingStatus
from app.models.run import RunStatus
from app.repositories.engagements import EngagementRepository
from app.repositories.findings import FindingRepository
from app.repositories.overview import OverviewRepository
from app.repositories.runs import RunRepository
from app.repositories.targets import TargetRepository
from app.schemas.engagement import (
    EngagementCreate,
    EngagementRead,
    ScopeDecisionRead,
)
from app.schemas.finding import FindingRead
from app.schemas.overview import OverviewRead
from app.schemas.pat import PATRead
from app.schemas.run import RunCreate, RunRead
from app.schemas.target import AttestationRequest, TargetCreate, TargetRead
from app.security.pat import list_pats, revoke_pat
from app.services.attack_path import build_attack_path_graph
from app.services.engagements import (
    activate_engagement,
    create_engagement,
    emergency_stop,
)
from app.services.findings import set_finding_status
from app.services.reports import generate_engagement_report
from app.services.runs import get_run, start_run, stop_run
from app.services.targets import list_targets, register_target

logger = logging.getLogger("secops.mcp.server")

MCP_INSTRUCTIONS = (
    "Security-Ops is an AUTHORIZED penetration-testing product. Every scan is "
    "gated: a run against a target is refused unless the engagement is ACTIVE and "
    "unexpired, the target is in scope and not excluded, and the target is covered "
    "by a currently-valid attestation. Use scope-check tools to preview a decision; "
    "register + attest targets and activate an engagement before starting a run. "
    "All tools act within your organization only."
)

#: The one FastMCP instance. Stateless streamable-HTTP with JSON responses; the
#: path is "/" because ``app.main`` mounts the whole app at "/mcp" (→ "/mcp/").
mcp = FastMCP(
    "security-ops",
    instructions=MCP_INSTRUCTIONS,
    stateless_http=True,
    json_response=True,
    streamable_http_path="/",
    # The MCP transport's DNS-rebinding Host/Origin check is off: it would reject
    # the deploy host. McpHttpGuard (in front of this app) does the HTTP 401 and
    # the Origin allow-list. Bearer auth inside each tool stays as defence in depth.
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    ),
)


# ---------------------------------------------------------------------------
# Coercion helpers (JSON-native tool inputs → domain types), fail-clean.
# ---------------------------------------------------------------------------
def _as_uuid(value: str, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValidationAppError(
            f"{field} must be a valid UUID", code="invalid_uuid", detail={"field": field}
        ) from exc


def _page(items: list[Any], total: int, limit: int, offset: int) -> dict[str, Any]:
    """The same ``Page`` envelope the REST list endpoints return."""
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def _coerce_enum(enum_cls, value, field: str):
    if value is None:
        return None
    try:
        return enum_cls(value)
    except ValueError as exc:
        allowed = [e.value for e in enum_cls]
        raise ValidationAppError(
            f"invalid {field}: {value!r}",
            code="invalid_enum",
            detail={"field": field, "allowed": allowed},
        ) from exc


async def _load_engagement(ctx: McpContext, engagement_id: uuid.UUID):
    engagement = await EngagementRepository(ctx.session).get(engagement_id)
    if engagement is None or engagement.org_id != ctx.org.id:
        raise NotFoundError("Engagement not found")
    return engagement


async def _load_target(ctx: McpContext, target_id: uuid.UUID):
    target = await TargetRepository(ctx.session).get(target_id)
    if target is None or target.org_id != ctx.org.id:
        raise NotFoundError("Target not found")
    return target


async def _load_run(ctx: McpContext, run_id: uuid.UUID):
    run = await get_run(ctx.session, run_id)
    if run is None or run.org_id != ctx.org.id:
        raise NotFoundError("Run not found")
    return run


async def _load_finding(ctx: McpContext, finding_id: uuid.UUID):
    finding = await FindingRepository(ctx.session).get(finding_id)
    if finding is None or finding.org_id != ctx.org.id:
        raise NotFoundError("Finding not found")
    return finding


# ---------------------------------------------------------------------------
# Implementations (the unit-tested seam) — each takes a resolved McpContext.
# ---------------------------------------------------------------------------
async def _overview_impl(ctx: McpContext) -> dict[str, Any]:
    summary = await OverviewRepository(ctx.session).summary(ctx.org.id)
    return OverviewRead.model_validate(summary).model_dump(mode="json")


async def _engagements_list_impl(ctx: McpContext, *, limit: int, offset: int) -> dict[str, Any]:
    items, total = await EngagementRepository(ctx.session).list_for_org(
        ctx.org.id, limit=limit, offset=offset
    )
    return _page(
        [EngagementRead.model_validate(e).model_dump(mode="json") for e in items],
        total,
        limit,
        offset,
    )


async def _engagements_get_impl(ctx: McpContext, engagement_id: uuid.UUID) -> dict[str, Any]:
    engagement = await _load_engagement(ctx, engagement_id)
    return EngagementRead.model_validate(engagement).model_dump(mode="json")


async def _engagements_create_impl(ctx: McpContext, payload: EngagementCreate) -> dict[str, Any]:
    engagement = await create_engagement(
        ctx.session, org=ctx.org, actor=ctx.user, data=payload
    )
    return EngagementRead.model_validate(engagement).model_dump(mode="json")


async def _engagements_activate_impl(ctx: McpContext, engagement_id: uuid.UUID) -> dict[str, Any]:
    engagement = await _load_engagement(ctx, engagement_id)
    activated = await activate_engagement(ctx.session, engagement=engagement, actor=ctx.user)
    return EngagementRead.model_validate(activated).model_dump(mode="json")


async def _engagements_stop_impl(ctx: McpContext, engagement_id: uuid.UUID) -> dict[str, Any]:
    engagement = await _load_engagement(ctx, engagement_id)
    stopped = await emergency_stop(ctx.session, engagement=engagement, actor=ctx.user)
    return EngagementRead.model_validate(stopped).model_dump(mode="json")


async def _engagements_scope_check_impl(
    ctx: McpContext, engagement_id: uuid.UUID, target: str
) -> dict[str, Any]:
    await _load_engagement(ctx, engagement_id)  # tenant check
    decision = await check_scope(ctx.session, engagement_id, target)
    return ScopeDecisionRead.model_validate(decision).model_dump(mode="json")


async def _engagements_report_impl(
    ctx: McpContext, engagement_id: uuid.UUID
) -> dict[str, Any]:
    engagement = await _load_engagement(ctx, engagement_id)
    report_markdown = await generate_engagement_report(ctx.session, engagement=engagement)
    return {"engagement_id": str(engagement.id), "report_markdown": report_markdown}


async def _attack_path_impl(
    ctx: McpContext, engagement_id: uuid.UUID
) -> dict[str, Any]:
    """Derive the engagement's attack-path graph from its findings (read-only).

    Tenant-checked via ``_load_engagement``; delegates to the SAME pure builder the
    HTTP route uses, so an agent and the console see the identical graph. Mutates
    nothing.
    """
    engagement = await _load_engagement(ctx, engagement_id)
    findings, _total = await FindingRepository(ctx.session).list_for_engagement(
        engagement.id
    )
    return build_attack_path_graph(engagement, findings).model_dump(mode="json")


async def _targets_list_impl(ctx: McpContext, *, limit: int, offset: int) -> dict[str, Any]:
    items, total = await list_targets(ctx.session, org=ctx.org, limit=limit, offset=offset)
    return _page(
        [TargetRead.model_validate(t).model_dump(mode="json") for t in items],
        total,
        limit,
        offset,
    )


async def _targets_get_impl(ctx: McpContext, target_id: uuid.UUID) -> dict[str, Any]:
    target = await _load_target(ctx, target_id)
    return TargetRead.model_validate(target).model_dump(mode="json")


async def _targets_register_impl(ctx: McpContext, payload: TargetCreate) -> dict[str, Any]:
    target = await register_target(ctx.session, org=ctx.org, actor=ctx.user, data=payload)
    return TargetRead.model_validate(target).model_dump(mode="json")


async def _targets_attestation_challenge_impl(
    ctx: McpContext, target_id: uuid.UUID
) -> dict[str, Any]:
    target = await _load_target(ctx, target_id)
    from app.models.target import TargetKind

    if target.kind == TargetKind.CLOUD_ACCOUNT:
        return cloud_instructions(target)
    return proof_instructions(target)


async def _targets_attest_impl(
    ctx: McpContext, target_id: uuid.UUID, payload: AttestationRequest
) -> dict[str, Any]:
    await _load_target(ctx, target_id)  # tenant check
    target = await attest_target(
        ctx.session,
        target_id,
        principal=ctx.user,
        method=payload.method,
        checkbox_ack=payload.checkbox_ack,
        typed_confirmation=payload.typed_confirmation,
        justification=payload.justification,
        evidence=payload.evidence,
        expires_at=payload.expires_at,
        # PAT principals resolve to OPERATOR (never ADMIN), so the admin-only
        # SELF_ATTESTED / BREAK_GLASS methods are unavailable over MCP by design —
        # a leaked token cannot self-authorize a target without a proof.
        actor_is_admin=ctx.user.role == UserRole.ADMIN,
    )
    await ctx.session.commit()
    return TargetRead.model_validate(target).model_dump(mode="json")


async def _runs_list_impl(
    ctx: McpContext, *, status: RunStatus | None, limit: int, offset: int
) -> dict[str, Any]:
    items, total = await RunRepository(ctx.session).list_for_org(
        ctx.org.id, status=status, limit=limit, offset=offset
    )
    return _page(
        [RunRead.model_validate(r).model_dump(mode="json") for r in items],
        total,
        limit,
        offset,
    )


async def _runs_get_impl(ctx: McpContext, run_id: uuid.UUID) -> dict[str, Any]:
    run = await _load_run(ctx, run_id)
    return RunRead.model_validate(run).model_dump(mode="json")


async def _runs_start_impl(
    ctx: McpContext, engagement_id: uuid.UUID, payload: RunCreate
) -> dict[str, Any]:
    """Start a scan run — THE gate-enforced path (identical to the HTTP route).

    ``start_run`` runs ``enforce_scope`` for every target BEFORE any run is created;
    an unauthorized target raises an ``AuthorizationDenied`` that surfaces to the
    agent as a tool error and creates nothing.
    """
    engagement = await _load_engagement(ctx, engagement_id)
    run = await start_run(ctx.session, engagement=engagement, actor=ctx.user, data=payload)
    return RunRead.model_validate(run).model_dump(mode="json")


async def _runs_stop_impl(ctx: McpContext, run_id: uuid.UUID) -> dict[str, Any]:
    run = await _load_run(ctx, run_id)
    stopped = await stop_run(ctx.session, run=run, actor=ctx.user)
    return RunRead.model_validate(stopped).model_dump(mode="json")


async def _runs_findings_impl(
    ctx: McpContext, run_id: uuid.UUID, *, limit: int, offset: int
) -> dict[str, Any]:
    await _load_run(ctx, run_id)  # tenant check
    items, total = await FindingRepository(ctx.session).list_for_run(
        run_id, limit=limit, offset=offset
    )
    return _page(
        [FindingRead.model_validate(f).model_dump(mode="json") for f in items],
        total,
        limit,
        offset,
    )


async def _findings_list_impl(
    ctx: McpContext,
    *,
    severity: FindingSeverity | None,
    status: FindingStatus | None,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    items, total = await FindingRepository(ctx.session).list_for_org(
        ctx.org.id, severity=severity, status=status, limit=limit, offset=offset
    )
    return _page(
        [FindingRead.model_validate(f).model_dump(mode="json") for f in items],
        total,
        limit,
        offset,
    )


async def _findings_get_impl(ctx: McpContext, finding_id: uuid.UUID) -> dict[str, Any]:
    finding = await _load_finding(ctx, finding_id)
    return FindingRead.model_validate(finding).model_dump(mode="json")


async def _findings_handoff_impl(ctx: McpContext, finding_id: uuid.UUID) -> dict[str, Any]:
    finding = await _load_finding(ctx, finding_id)
    engagement = None
    run = None
    if finding.engagement_id is not None:
        engagement = await EngagementRepository(ctx.session).get(finding.engagement_id)
    if finding.run_id is not None:
        run = await RunRepository(ctx.session).get(finding.run_id)
    finding = await handoff_finding(
        ctx.session, finding=finding, actor=ctx.user, engagement=engagement, run=run
    )
    await ctx.session.commit()
    return FindingRead.model_validate(finding).model_dump(mode="json")


async def _findings_set_status_impl(
    ctx: McpContext,
    finding_id: uuid.UUID,
    status: FindingStatus,
    closure_reason: str | None = None,
) -> dict[str, Any]:
    """Operator triage over MCP — set a finding's status (audited), agent/human parity.

    Reuses ``_load_finding`` for the tenant check and delegates to the SAME
    ``app.services.findings.set_finding_status`` the HTTP route calls; owns the
    commit. Setting ``HANDED_OFF`` is refused (use ``findings_handoff``).
    """
    finding = await _load_finding(ctx, finding_id)
    finding = await set_finding_status(
        ctx.session,
        finding=finding,
        new_status=status,
        actor=ctx.user,
        closure_reason=closure_reason,
    )
    await ctx.session.commit()
    return FindingRead.model_validate(finding).model_dump(mode="json")


# --- Personal access tokens (agent-key hygiene) ----------------------------
# DELIBERATE PARITY EXCEPTION: there is NO `pats_create` tool. Minting a durable
# credential is a human trust act — an agent creating new long-lived keys for
# itself is a credential-/privilege-persistence footgun, doubly so in an
# offensive-security product. Agents get read + revoke (so rotation and cleanup
# are fully agent-doable); creation stays human-only via `POST /api/v1/pats`.
async def _pats_list_impl(ctx: McpContext) -> dict[str, Any]:
    rows = await list_pats(ctx.session, owner_user_id=ctx.user.id, org_slug=ctx.org.slug)
    return {"items": [PATRead.model_validate(p).model_dump(mode="json") for p in rows]}


async def _pats_revoke_impl(ctx: McpContext, pat_id: uuid.UUID) -> dict[str, Any]:
    record = await revoke_pat(
        ctx.session, pat_id, owner_user_id=ctx.user.id, org_slug=ctx.org.slug
    )
    if record is None:
        raise NotFoundError("Personal access token not found")
    await ctx.session.commit()
    return PATRead.model_validate(record).model_dump(mode="json")


# ---------------------------------------------------------------------------
# Registered tools — thin wrappers that acquire the scope and delegate.
# ---------------------------------------------------------------------------
@mcp.tool()
async def overview_get() -> dict:
    """Org-scoped dashboard summary (engagement/target/run/finding counts)."""
    async with mcp_scope() as ctx:
        return await _overview_impl(ctx)


@mcp.tool()
async def engagements_list(limit: int = 50, offset: int = 0) -> dict:
    """List your organization's engagements (newest first)."""
    async with mcp_scope() as ctx:
        return await _engagements_list_impl(ctx, limit=limit, offset=offset)


@mcp.tool()
async def engagements_get(engagement_id: str) -> dict:
    """Fetch one engagement by id (your org only)."""
    async with mcp_scope() as ctx:
        return await _engagements_get_impl(ctx, _as_uuid(engagement_id, "engagement_id"))


@mcp.tool()
async def engagements_create(payload: EngagementCreate) -> dict:
    """Create a DRAFT engagement with its scope-of-engagement (audited)."""
    async with mcp_scope() as ctx:
        return await _engagements_create_impl(ctx, payload)


@mcp.tool()
async def engagements_activate(engagement_id: str) -> dict:
    """Activate an engagement. Fails closed unless every in-scope rule is covered
    by a valid attested target."""
    async with mcp_scope() as ctx:
        return await _engagements_activate_impl(ctx, _as_uuid(engagement_id, "engagement_id"))


@mcp.tool()
async def engagements_stop(engagement_id: str) -> dict:
    """Emergency-stop an engagement (kill-switch + STOPPED, audited)."""
    async with mcp_scope() as ctx:
        return await _engagements_stop_impl(ctx, _as_uuid(engagement_id, "engagement_id"))


@mcp.tool()
async def engagements_scope_check(engagement_id: str, target: str) -> dict:
    """Dry-run the authorization gate for a target (no audit, no side effect)."""
    async with mcp_scope() as ctx:
        return await _engagements_scope_check_impl(
            ctx, _as_uuid(engagement_id, "engagement_id"), target
        )


@mcp.tool()
async def engagements_report(engagement_id: str) -> dict:
    """Export the branded engagement report as ``{engagement_id, report_markdown}``."""
    async with mcp_scope() as ctx:
        return await _engagements_report_impl(ctx, _as_uuid(engagement_id, "engagement_id"))


@mcp.tool()
async def engagements_attack_path(engagement_id: str) -> dict:
    """Derive the engagement's attack-path/exposure graph from its findings
    (engagement root -> affected host -> finding leaf, severity rolled up). Read-only,
    your org only — the same graph the console renders."""
    async with mcp_scope() as ctx:
        return await _attack_path_impl(ctx, _as_uuid(engagement_id, "engagement_id"))


@mcp.tool()
async def targets_list(limit: int = 50, offset: int = 0) -> dict:
    """List your organization's registered authorized targets."""
    async with mcp_scope() as ctx:
        return await _targets_list_impl(ctx, limit=limit, offset=offset)


@mcp.tool()
async def targets_get(target_id: str) -> dict:
    """Fetch one authorized target by id (your org only)."""
    async with mcp_scope() as ctx:
        return await _targets_get_impl(ctx, _as_uuid(target_id, "target_id"))


@mcp.tool()
async def targets_register(payload: TargetCreate) -> dict:
    """Register a new (UNATTESTED) target. Registration alone never authorizes a scan."""
    async with mcp_scope() as ctx:
        return await _targets_register_impl(ctx, payload)


@mcp.tool()
async def targets_attestation_challenge(target_id: str) -> dict:
    """Return the per-target challenge token + copy-paste ownership-proof instructions."""
    async with mcp_scope() as ctx:
        return await _targets_attestation_challenge_impl(ctx, _as_uuid(target_id, "target_id"))


@mcp.tool()
async def targets_attest(target_id: str, payload: AttestationRequest) -> dict:
    """Attest a target so the gate treats it as scannable. External-proof methods
    are VERIFIED live server-side; a proof that does not resolve is refused."""
    async with mcp_scope() as ctx:
        return await _targets_attest_impl(ctx, _as_uuid(target_id, "target_id"), payload)


@mcp.tool()
async def runs_list(status: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    """List your organization's runs (optionally filtered by lifecycle status)."""
    async with mcp_scope() as ctx:
        return await _runs_list_impl(
            ctx,
            status=_coerce_enum(RunStatus, status, "status"),
            limit=limit,
            offset=offset,
        )


@mcp.tool()
async def runs_get(run_id: str) -> dict:
    """Fetch one run by id (your org only)."""
    async with mcp_scope() as ctx:
        return await _runs_get_impl(ctx, _as_uuid(run_id, "run_id"))


@mcp.tool()
async def runs_start(engagement_id: str, payload: RunCreate) -> dict:
    """Start a scan run — GATE-ENFORCED. Every target must be in scope and covered
    by a valid attestation under an ACTIVE, unexpired engagement, or the run is
    refused and nothing is created."""
    async with mcp_scope() as ctx:
        return await _runs_start_impl(ctx, _as_uuid(engagement_id, "engagement_id"), payload)


@mcp.tool()
async def runs_stop(run_id: str) -> dict:
    """Stop a run (audited RUN_STOPPED)."""
    async with mcp_scope() as ctx:
        return await _runs_stop_impl(ctx, _as_uuid(run_id, "run_id"))


@mcp.tool()
async def runs_findings(run_id: str, limit: int = 50, offset: int = 0) -> dict:
    """List one run's findings (your org only)."""
    async with mcp_scope() as ctx:
        return await _runs_findings_impl(ctx, _as_uuid(run_id, "run_id"), limit=limit, offset=offset)


@mcp.tool()
async def findings_list(
    severity: str | None = None,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List your organization's findings inbox (optional severity/status filters)."""
    async with mcp_scope() as ctx:
        return await _findings_list_impl(
            ctx,
            severity=_coerce_enum(FindingSeverity, severity, "severity"),
            status=_coerce_enum(FindingStatus, status, "status"),
            limit=limit,
            offset=offset,
        )


@mcp.tool()
async def findings_get(finding_id: str) -> dict:
    """Fetch one finding by id (your org only)."""
    async with mcp_scope() as ctx:
        return await _findings_get_impl(ctx, _as_uuid(finding_id, "finding_id"))


@mcp.tool()
async def findings_set_status(finding_id: str, status: str) -> dict:
    """Triage a finding — set its status (VERIFIED / FALSE_POSITIVE / REMEDIATED, or
    NEW to reopen), audited. Agent/human parity with the console. HANDED_OFF is
    refused here — use ``findings_handoff`` to hand a confirmed finding to Brigade."""
    async with mcp_scope() as ctx:
        return await _findings_set_status_impl(
            ctx,
            _as_uuid(finding_id, "finding_id"),
            _coerce_enum(FindingStatus, status, "status"),
        )


@mcp.tool()
async def findings_handoff(finding_id: str) -> dict:
    """Hand a confirmed finding to Brigade for triage/remediation (audited)."""
    async with mcp_scope() as ctx:
        return await _findings_handoff_impl(ctx, _as_uuid(finding_id, "finding_id"))


@mcp.tool()
async def pats_list() -> dict:
    """List your agent access tokens (non-secret metadata), newest first."""
    async with mcp_scope() as ctx:
        return await _pats_list_impl(ctx)


@mcp.tool()
async def pats_revoke(pat_id: str) -> dict:
    """Revoke one of your agent access tokens (idempotent). Creating a new token
    is a human-only trust act — do it in the console (POST /api/v1/pats)."""
    async with mcp_scope() as ctx:
        return await _pats_revoke_impl(ctx, _as_uuid(pat_id, "pat_id"))


# ---------------------------------------------------------------------------
# ASGI mount
# ---------------------------------------------------------------------------
_asgi_app = None


def mcp_asgi_app():
    """Return the (memoized) ASGI app to mount at ``/mcp``.

    Order: :class:`McpHttpGuard` (401, OPTIONS, Origin) then
    :class:`BearerTokenMiddleware` (capture the bearer for the tools) then the
    streamable-HTTP app. Building it also creates ``mcp.session_manager``;
    ``app.main`` runs that manager's lifespan.
    """
    global _asgi_app
    if _asgi_app is None:
        _asgi_app = McpHttpGuard(BearerTokenMiddleware(mcp.streamable_http_app()))
    return _asgi_app


__all__ = ["mcp", "mcp_asgi_app", "MCP_INSTRUCTIONS"]
