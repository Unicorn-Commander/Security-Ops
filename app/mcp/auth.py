"""MCP call authentication + tenant scoping — the parity guarantee.

Every MCP tool runs inside :func:`mcp_scope`, which reproduces the exact
authorization chain the HTTP dependencies (:mod:`app.api.deps`) enforce, so an
agent gets parity with a human WITHOUT weakening any guardrail:

1. **Authenticate** the Bearer credential (:func:`resolve_principal`): a durable
   Personal Access Token (``secops_pat_…``, verified against its stored hash) OR a
   uchub Keycloak JWT (reusing :func:`app.auth.sso.validate_token`). Both resolve
   the same :class:`~app.auth.sso.AuthUser`. The development bypass is honored only
   when it is for the HTTP surface too.
2. **Entitle** the principal (:func:`require_entitlement_user`) on the
   ``security-ops`` SKU — the identical gate as ``app.api.deps.EntitledUser``.
3. **Scope** the request to the caller's tenant by reusing
   ``app.api.deps.get_current_org`` verbatim — which resolves the org by slug AND
   arms Postgres RLS (the ``app.current_org_id`` GUC) for the session, so every
   query the tool issues is tenant-filtered exactly as an HTTP request would be.

The Bearer token is captured off the ASGI request by
:class:`BearerTokenMiddleware` (which wraps the mounted MCP app) into a contextvar
the tools read — the streamable-HTTP transport handles each stateless call inline
in the same task, so the contextvar propagates into the tool body.

Import direction: this module sits beside the tools and reuses auth / deps /
security.pat; nothing in the core app imports it.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_org
from app.auth.entitlement import has_entitlement
from app.auth.sso import (
    AuthUser,
    KeycloakValidationError,
    UserRole,
    _auth_bypass_active,
    _bypass_principal,
    keycloak_enabled,
    principal_from_claims,
    validate_token,
)
from app.core.config import settings
from app.db.session import get_session
from app.models.organization import Organization
from app.security.pat import is_pat_token, verify_pat

logger = logging.getLogger("secops.mcp.auth")

# The raw Bearer token for the in-flight MCP call, captured by the ASGI wrapper.
_current_token: ContextVar[str | None] = ContextVar("mcp_bearer_token", default=None)


class McpAuthError(Exception):
    """An MCP call could not be authenticated / authorized.

    Raised inside a tool so FastMCP surfaces it as a tool error (the agent-facing
    analogue of the HTTP 401/403 the console would receive). It never leaks token
    material — only a short reason.
    """


def set_current_token(token: str | None):
    """Bind the in-flight call's Bearer token; returns the contextvar reset handle."""
    return _current_token.set(token)


def get_current_token() -> str | None:
    """The Bearer token captured for the in-flight MCP call (or ``None``)."""
    return _current_token.get()


class BearerTokenMiddleware:
    """Pure-ASGI wrapper that lifts ``Authorization: Bearer`` into the contextvar.

    Wraps the mounted MCP app so each tool can read the caller's credential without
    the transport threading it through. Resets the contextvar on the way out so a
    pooled task never inherits a previous call's token.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        token = _extract_bearer(scope.get("headers") or [])
        reset = set_current_token(token)
        try:
            await self.app(scope, receive, send)
        finally:
            _current_token.reset(reset)


def _extract_bearer(headers: list[tuple[bytes, bytes]]) -> str | None:
    for key, value in headers:
        if key.lower() == b"authorization":
            raw = value.decode("latin-1").strip()
            if raw.lower().startswith("bearer "):
                return raw[7:].strip() or None
            return None
    return None


async def resolve_principal(session: AsyncSession, token: str | None) -> AuthUser:
    """Resolve a Bearer ``token`` to an :class:`AuthUser` (PAT or JWT).

    Refuses with :class:`McpAuthError` on a missing/invalid/unusable credential.
    The dev bypass is honored only under the same condition as the HTTP surface
    (``environment == development`` + ``SECOPS_AUTH_BYPASS``).
    """
    if _auth_bypass_active() and not token:
        return _bypass_principal()

    if not token:
        raise McpAuthError("missing bearer token")

    if is_pat_token(token):
        record = await verify_pat(session, token)
        if record is None:
            raise McpAuthError("invalid, revoked, or expired personal access token")
        return AuthUser(
            id=record.owner_user_id,
            email=record.owner_email,
            role=UserRole.OPERATOR,
            org_slug=record.org_slug,
            apps=list(record.scopes or []),
            attrs={"pat_id": str(record.id), "pat_name": record.name},
            auth_source="pat",
        )

    if not keycloak_enabled():
        raise McpAuthError("authentication is not configured")
    try:
        claims = await validate_token(token)
    except KeycloakValidationError as exc:
        raise McpAuthError(f"token verification failed: {exc}") from exc
    return principal_from_claims(claims, auth_source="keycloak")


def require_entitlement_user(user: AuthUser) -> None:
    """Enforce the ``security-ops`` entitlement — the same gate as the HTTP deps."""
    sku = settings.entitlement_sku
    if not has_entitlement(user, sku):
        raise McpAuthError(f"entitlement required: {sku}")


@dataclass
class McpContext:
    """The resolved, tenant-scoped context handed to every MCP tool body."""

    session: AsyncSession
    org: Organization
    user: AuthUser


@asynccontextmanager
async def mcp_scope(
    *, session: AsyncSession | None = None
) -> AsyncIterator[McpContext]:
    """Authenticate + entitle + tenant-scope the in-flight MCP call.

    Yields an :class:`McpContext` (session bound to the caller's org under RLS,
    resolved principal). Reuses ``app.api.deps.get_current_org`` so tenant
    resolution + the ``app.current_org_id`` GUC behave identically to HTTP.

    ``session`` is injectable for tests; in production the request opens (and tears
    down, resetting the org GUC) its own session via ``app.db.session.get_session``.
    """
    token = get_current_token()

    if session is not None:
        user = await resolve_principal(session, token)
        require_entitlement_user(user)
        org = await get_current_org(user, session)
        yield McpContext(session=session, org=org, user=user)
        return

    agen = get_session()
    live = await agen.__anext__()
    try:
        user = await resolve_principal(live, token)
        require_entitlement_user(user)
        org = await get_current_org(user, live)
        yield McpContext(session=live, org=org, user=user)
    finally:
        # Runs get_session's teardown (rollback → clear org GUC → close).
        await agen.aclose()
