"""MCP surface tests — parity WITH the guardrails intact.

The MCP tools reuse the same service layer and authorization gate as the HTTP API,
so these tests assert the security-critical invariants directly against a real
in-memory session (no transport):

* the per-call scope (:func:`app.mcp.auth.mcp_scope`) authenticates a PAT and
  enforces the ``security-ops`` entitlement — a key lacking it is refused;
* a scan tool (``runs_start``) is refused by the gate when no attested target
  covers the target, exactly as the HTTP route would be;
* the read tools return the console's org-scoped shapes.
"""

from __future__ import annotations

import pytest

from app.auth.sso import AuthUser, UserRole
from app.authz.errors import AuthorizationDenied
from app.mcp.auth import McpAuthError, McpContext, mcp_scope, set_current_token
from app.mcp.server import (
    _attack_path_impl,
    _engagements_scope_check_impl,
    _overview_impl,
    _runs_start_impl,
    _targets_list_impl,
)
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.run import Run, RunMode, RunStatus
from app.schemas.run import RunCreate
from app.security.pat import create_pat
from tests.conftest import make_engagement, make_org, make_target


def _agent(org_slug: str = "pilot", apps=("security-ops",)) -> AuthUser:
    return AuthUser(
        id="agent-1",
        email="demo@example.invalid",
        role=UserRole.OPERATOR,
        org_slug=org_slug,
        apps=list(apps),
    )


def _ctx(session, org, user=None) -> McpContext:
    return McpContext(session=session, org=org, user=user or _agent(org.slug))


# ---------------------------------------------------------------------------
# Auth + entitlement gate (via mcp_scope)
# ---------------------------------------------------------------------------
async def test_mcp_scope_accepts_entitled_pat(db_session):
    org = await make_org(db_session, slug="pilot")
    minted = await create_pat(
        db_session, "agent-1", "k", ["security-ops"], org_slug=org.slug
    )
    await db_session.commit()

    set_current_token(minted.plaintext)
    try:
        async with mcp_scope(session=db_session) as ctx:
            assert ctx.org.id == org.id
            assert ctx.user.auth_source == "pat"
            assert ctx.user.org_slug == "pilot"
    finally:
        set_current_token(None)


async def test_mcp_scope_refuses_pat_without_entitlement(db_session):
    org = await make_org(db_session, slug="pilot")
    # Minted with NO entitlement SKUs → the entitlement gate must bite.
    minted = await create_pat(db_session, "agent-1", "k", [], org_slug=org.slug)
    await db_session.commit()

    set_current_token(minted.plaintext)
    try:
        with pytest.raises(McpAuthError):
            async with mcp_scope(session=db_session):
                pass
    finally:
        set_current_token(None)


async def test_mcp_scope_refuses_bad_pat(db_session):
    await make_org(db_session, slug="pilot")
    set_current_token("secops_pat_not-a-real-key")
    try:
        with pytest.raises(McpAuthError):
            async with mcp_scope(session=db_session):
                pass
    finally:
        set_current_token(None)


# ---------------------------------------------------------------------------
# The gate still refuses a scan the same way it does over HTTP
# ---------------------------------------------------------------------------
async def test_runs_start_tool_refused_without_attested_scope(db_session):
    org = await make_org(db_session, slug="pilot")
    # ACTIVE engagement scoped to example.com, but NO attested target covers it.
    engagement = await make_engagement(db_session, org)
    ctx = _ctx(db_session, org)

    with pytest.raises(AuthorizationDenied):
        await _runs_start_impl(
            ctx, engagement.id, RunCreate(targets=["example.com"])
        )

    # And nothing was created — the denial creates no run.
    from app.repositories.runs import RunRepository

    _items, total = await RunRepository(db_session).list_for_org(org.id)
    assert total == 0


async def test_scope_check_tool_allows_attested_target(db_session):
    org = await make_org(db_session, slug="pilot")
    await make_target(db_session, org, value="example.com")  # attested-and-valid
    engagement = await make_engagement(db_session, org)
    ctx = _ctx(db_session, org)

    decision = await _engagements_scope_check_impl(ctx, engagement.id, "example.com")
    assert decision["allowed"] is True
    assert decision["code"] == "allowed"


# ---------------------------------------------------------------------------
# Read tools return the console's org-scoped shapes
# ---------------------------------------------------------------------------
async def test_overview_and_list_tools_are_org_scoped(db_session):
    org = await make_org(db_session, slug="pilot")
    other = await make_org(db_session, slug="other")
    await make_target(db_session, org, value="a.example.com")
    await make_target(db_session, other, value="z.example.com")  # noise
    ctx = _ctx(db_session, org)

    overview = await _overview_impl(ctx)
    assert overview["targets"]["total"] == 1

    page = await _targets_list_impl(ctx, limit=50, offset=0)
    assert page["total"] == 1
    assert page["items"][0]["value"] == "a.example.com"


async def test_attack_path_tool_derives_graph_and_is_tenant_isolated(db_session):
    import uuid

    import pytest

    from app.core.errors import NotFoundError

    org = await make_org(db_session, slug="pilot")
    other = await make_org(db_session, slug="other")
    engagement = await make_engagement(db_session, org)
    other_engagement = await make_engagement(db_session, other)

    run = Run(
        id=uuid.uuid4(), engagement_id=engagement.id, org_id=org.id,
        mode=RunMode.STANDARD, model_profile="hybrid-local-sweep-verify",
        targets=["example.com"], status=RunStatus.COMPLETED,
    )
    db_session.add(run)
    await db_session.flush()
    db_session.add(Finding(
        id=uuid.uuid4(), run_id=run.id, engagement_id=engagement.id, org_id=org.id,
        title="SQLi", severity=FindingSeverity.CRITICAL, status=FindingStatus.NEW,
        endpoint="https://app.example.com/login",
    ))
    await db_session.flush()

    ctx = _ctx(db_session, org)
    graph = await _attack_path_impl(ctx, engagement.id)
    # Same console shape: one host derived from the finding, worst severity rolled up.
    assert graph["summary"]["finding_count"] == 1
    assert graph["summary"]["host_count"] == 1
    assert graph["summary"]["max_severity"] == "CRITICAL"
    assert any(n["type"] == "host" and n["label"] == "app.example.com" for n in graph["nodes"])

    # Another org's engagement is a 404 for this caller — same gate as the HTTP route.
    with pytest.raises(NotFoundError):
        await _attack_path_impl(ctx, other_engagement.id)
