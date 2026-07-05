"""Operator authentication — suite-native Keycloak OIDC (realm ``uchub``).

This module is the physical home of the blueprint's ``keycloak`` + ``roles`` +
``middleware`` surfaces (they are aliased onto ``app.auth.keycloak``,
``app.auth.roles`` and ``app.auth.middleware`` in ``app.auth.__init__`` so every
consumer's import path resolves). It mirrors the Brigade suite pattern:

  * validate a Bearer JWT against the realm's JWKS (cached), issuer + audience,
  * map realm/client roles -> a coarse :class:`UserRole`,
  * derive suite entitlement slugs from ``app-<slug>`` roles,
  * expose FastAPI current-user dependencies.

This is the OPERATOR authorization (who may drive the app). It is deliberately
separate from the TARGET authorization gate in :mod:`app.authz` (what a scan may
touch). Keep the two concerns apart.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import AppError, ForbiddenError
from app.db.session import get_session

logger = logging.getLogger("secops.auth.sso")

# FastAPI extracts ``Authorization: Bearer <token>``; auto_error=False so we can
# render the uniform error envelope (and support the dev bypass) ourselves.
bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Keycloak token validation
# ---------------------------------------------------------------------------
class KeycloakValidationError(Exception):
    """Raised when a Bearer token cannot be verified against the realm."""


def keycloak_enabled() -> bool:
    """Whether SSO token validation is active (config-driven)."""
    return bool(settings.keycloak_enabled)


# In-process JWKS cache: {jwks_uri: (fetched_monotonic, jwks_dict)}.
_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _jwks_uri() -> str:
    issuer = (settings.keycloak_issuer or "").rstrip("/")
    if not issuer:
        raise KeycloakValidationError("keycloak_issuer is not configured")
    return f"{issuer}/protocol/openid-connect/certs"


async def _fetch_jwks(uri: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(uri)
        resp.raise_for_status()
        return resp.json()


async def _get_jwks(*, force: bool = False) -> dict[str, Any]:
    uri = _jwks_uri()
    now = time.monotonic()
    cached = _jwks_cache.get(uri)
    ttl = max(int(settings.keycloak_jwks_ttl or 0), 0)
    if cached and not force and (now - cached[0]) < ttl:
        return cached[1]
    jwks = await _fetch_jwks(uri)
    _jwks_cache[uri] = (now, jwks)
    return jwks


def _find_jwk(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
    for key in jwks.get("keys", []) or []:
        if key.get("kid") == kid:
            return key
    return None


async def _signing_key_for(kid: str) -> Any:
    jwks = await _get_jwks()
    jwk = _find_jwk(jwks, kid)
    if jwk is None:
        # Keys may have rotated since the last cache fill — refresh once.
        jwks = await _get_jwks(force=True)
        jwk = _find_jwk(jwks, kid)
    if jwk is None:
        raise KeycloakValidationError(f"no signing key found for kid={kid!r}")
    return RSAAlgorithm.from_jwk(json.dumps(jwk))


async def validate_token(token: str) -> dict:
    """Verify a Bearer JWT and return its claims.

    Verifies the RS256 signature against the realm JWKS (cached, with a single
    forced refresh on unknown ``kid``), the issuer, and the audience (when
    ``settings.keycloak_audience`` is set). Raises :class:`KeycloakValidationError`
    on any failure. This is the low-level primitive; request wiring lives in
    :func:`get_current_user`.
    """
    if not token or not token.strip():
        raise KeycloakValidationError("empty bearer token")

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:  # malformed token
        raise KeycloakValidationError(f"malformed token header: {exc}") from exc

    kid = header.get("kid")
    if not kid:
        raise KeycloakValidationError("token header missing 'kid'")

    try:
        signing_key = await _signing_key_for(kid)
    except KeycloakValidationError:
        raise
    except Exception as exc:  # network / JWKS fetch problems
        raise KeycloakValidationError(f"unable to load signing keys: {exc}") from exc

    audience = settings.keycloak_audience
    issuer = settings.keycloak_issuer or None
    options = {"verify_aud": audience is not None}
    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            leeway=30,  # tolerate minor clock skew
            options=options,
        )
    except jwt.PyJWTError as exc:
        raise KeycloakValidationError(f"token verification failed: {exc}") from exc
    return claims


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
class UserRole(str, Enum):
    """Coarse operator role, resolved from realm/client roles."""

    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"


_ADMIN_ROLE_NAMES = {
    "admin",
    "administrator",
    "realm-admin",
    "security-ops-admin",
    "secops-admin",
    "app-security-ops-admin",
}
_OPERATOR_ROLE_NAMES = {
    "operator",
    "security-ops-operator",
    "secops-operator",
    "pentester",
    "app-security-ops-operator",
}
_VIEWER_ROLE_NAMES = {
    "viewer",
    "read-only",
    "readonly",
    "security-ops-viewer",
    "app-security-ops-viewer",
}


def map_keycloak_roles(roles: list[str]) -> UserRole:
    """Collapse a list of realm/client role strings into a single UserRole.

    Precedence: ADMIN > OPERATOR > VIEWER; anything unrecognized defaults to the
    least-privileged VIEWER.
    """
    normalized = {r.strip().lower() for r in roles if isinstance(r, str) and r.strip()}
    if normalized & _ADMIN_ROLE_NAMES:
        return UserRole.ADMIN
    if normalized & _OPERATOR_ROLE_NAMES:
        return UserRole.OPERATOR
    # VIEWER role names are explicit but VIEWER is also the safe default.
    return UserRole.VIEWER


# ---------------------------------------------------------------------------
# Principal / current-user dependencies
# ---------------------------------------------------------------------------
@dataclass
class AuthUser:
    """The authenticated operator principal (result of SSO validation)."""

    id: str
    email: str | None = None
    role: UserRole = UserRole.VIEWER
    org_slug: str | None = None
    apps: list[str] = field(default_factory=list)
    attrs: dict = field(default_factory=dict)
    auth_source: str = "keycloak"

    def has_app(self, slug: str) -> bool:
        """Whether this principal carries the given suite entitlement slug."""
        return slug in self.apps


def _collect_roles(claims: dict) -> list[str]:
    """Gather realm roles + all client roles, de-duplicated, order-preserving."""
    roles: list[str] = []
    realm = claims.get("realm_access") or {}
    if isinstance(realm, dict):
        roles.extend(realm.get("roles") or [])
    resource = claims.get("resource_access") or {}
    if isinstance(resource, dict):
        for client in resource.values():
            if isinstance(client, dict):
                roles.extend(client.get("roles") or [])
    seen: set[str] = set()
    ordered: list[str] = []
    for role in roles:
        if isinstance(role, str) and role not in seen:
            seen.add(role)
            ordered.append(role)
    return ordered


def _derive_apps(roles: list[str]) -> list[str]:
    """Suite convention: entitlement slugs come from ``app-<slug>`` realm roles."""
    apps: list[str] = []
    seen: set[str] = set()
    for role in roles:
        if role.startswith("app-"):
            slug = role[len("app-") :]
            if slug and slug not in seen:
                seen.add(slug)
                apps.append(slug)
    return apps


def _derive_org_slug(claims: dict) -> str | None:
    for key in ("org_slug", "organization", "org", "orgSlug"):
        value = claims.get(key)
        if isinstance(value, str) and value:
            return value
    groups = claims.get("groups")
    if isinstance(groups, list):
        for group in groups:
            if isinstance(group, str) and group.startswith("/orgs/"):
                slug = group[len("/orgs/") :].strip("/")
                if slug:
                    return slug
    return None


def principal_from_claims(claims: dict, *, auth_source: str = "keycloak") -> AuthUser:
    """Build an :class:`AuthUser` from verified JWT claims."""
    roles = _collect_roles(claims)
    subject = claims.get("sub") or claims.get("preferred_username")
    if not subject:
        raise KeycloakValidationError("token missing subject ('sub') claim")
    attrs = {
        "preferred_username": claims.get("preferred_username"),
        "name": claims.get("name"),
        "given_name": claims.get("given_name"),
        "family_name": claims.get("family_name"),
        "groups": claims.get("groups"),
        "realm_roles": roles,
    }
    attrs = {k: v for k, v in attrs.items() if v is not None}
    return AuthUser(
        id=str(subject),
        email=claims.get("email"),
        role=map_keycloak_roles(roles),
        org_slug=_derive_org_slug(claims),
        apps=_derive_apps(roles),
        attrs=attrs,
        auth_source=auth_source,
    )


def _bypass_principal() -> AuthUser:
    """Full-access principal for local development (``SECOPS_AUTH_BYPASS=1``).

    Only ever reachable when ``settings.environment == 'development'`` — see
    :func:`_auth_bypass_active`.
    """
    return AuthUser(
        id="dev-bypass",
        email="dev-bypass@localhost",
        role=UserRole.ADMIN,
        org_slug="pilot",
        apps=[settings.entitlement_sku],
        attrs={"bypass": True, "preferred_username": "dev-bypass"},
        auth_source="bypass",
    )


def _auth_bypass_active() -> bool:
    return bool(settings.auth_bypass) and settings.environment == "development"


def _unauthorized(message: str) -> AppError:
    return AppError(message, code="unauthorized", status_code=401)


async def _resolve_user(
    creds: HTTPAuthorizationCredentials | None,
) -> AuthUser | None:
    """Shared token->principal resolution. Returns None when no/invalid creds.

    Raises :class:`KeycloakValidationError` only for a *present but invalid* token
    so callers can distinguish "no credentials" from "bad credentials".
    """
    if _auth_bypass_active():
        return _bypass_principal()
    if creds is None or not creds.credentials:
        return None
    if not keycloak_enabled():
        # No bypass and SSO disabled -> we cannot authenticate anyone.
        raise KeycloakValidationError("authentication is not configured")
    claims = await validate_token(creds.credentials)
    return principal_from_claims(claims, auth_source="keycloak")


async def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> AuthUser:
    """FastAPI dependency: require a valid SSO principal (or dev bypass).

    Raises a 401 :class:`AppError` when no valid Bearer token is present. The
    ``session`` is part of the contract (future DB-backed principal enrichment);
    Phase 1 does not query it.
    """
    try:
        user = await _resolve_user(creds)
    except KeycloakValidationError as exc:
        raise _unauthorized(str(exc)) from exc
    if user is None:
        raise _unauthorized("missing or invalid bearer token")
    return user


async def get_current_user_optional(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> AuthUser | None:
    """Like :func:`get_current_user` but returns None instead of raising."""
    try:
        return await _resolve_user(creds)
    except KeycloakValidationError:
        return None


def require_admin(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """FastAPI dependency: require the ADMIN operator role (else 403)."""
    if user.role != UserRole.ADMIN:
        raise ForbiddenError(
            "admin role required",
            detail={"required_role": UserRole.ADMIN.value, "role": user.role.value},
        )
    return user


__all__ = [
    "bearer_scheme",
    "KeycloakValidationError",
    "keycloak_enabled",
    "validate_token",
    "UserRole",
    "map_keycloak_roles",
    "AuthUser",
    "principal_from_claims",
    "get_current_user",
    "get_current_user_optional",
    "require_admin",
]
