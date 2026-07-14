"""Shared FastAPI dependencies for the HTTP API (spec §6).

Three request-scoped dependencies are wired here, and every business route in
``app.api.*`` is composed from them:

* :data:`DbSession`    — the request-scoped ``AsyncSession`` (from
  :func:`app.db.session.get_session`; the route/service owns commits).
* :data:`EntitledUser` — the authenticated operator principal, gated on the
  ``security-ops`` product entitlement (SSO via :func:`app.auth.sso.get_current_user`
  → entitlement via :func:`app.auth.entitlement.require_entitlement`).
* :data:`CurrentOrg`   — the caller's tenant :class:`~app.models.organization.Organization`,
  resolved from the principal's ``org_slug``.

The enforcement chain is transitive and that is deliberate: ``CurrentOrg``
depends on ``EntitledUser``, so *any* route that declares only ``org: CurrentOrg``
(e.g. the read/list endpoints) still requires a valid SSO principal AND the
entitlement before the handler runs — which is exactly the guarantee the router
docstrings assert ("enforced transitively via ``CurrentOrg``"). Because FastAPI
caches sub-dependencies by callable within a request, the SSO check, the
entitlement gate, and the DB session each resolve exactly once even when a route
also declares ``user: EntitledUser`` alongside ``org: CurrentOrg``.

Tenant resolution is fail-closed: a principal with no ``org_slug`` (or whose org
is not provisioned in this app's database) is refused with a 403 rather than
silently granted an empty/implicit tenant — a pentest product must never leak or
guess org context. The pilot org (slug ``pilot``) is created by
``scripts.seed_pilot``; the dev-bypass principal carries ``org_slug="pilot"`` to
match it.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.sso import AuthUser
from app.auth.entitlement import require_entitlement
from app.core.errors import ForbiddenError
from app.db.rls import set_org_context
from app.db.session import get_session
from app.models.organization import Organization

# ---------------------------------------------------------------------------
# Database session
# ---------------------------------------------------------------------------
#: The one request-scoped ``AsyncSession`` for the whole request. Repositories
#: and services own their transactions; this dependency never auto-commits (see
#: :func:`app.db.session.get_session`).
DbSession = Annotated[AsyncSession, Depends(get_session)]


# ---------------------------------------------------------------------------
# Operator principal (SSO + entitlement)
# ---------------------------------------------------------------------------
#: The authenticated operator, additionally required to hold the ``security-ops``
#: entitlement. ``require_entitlement()`` is invoked ONCE here (at import) so the
#: resulting callable is a single, stable dependency that FastAPI can cache and
#: de-duplicate across a request.
EntitledUser = Annotated[AuthUser, Depends(require_entitlement())]


# ---------------------------------------------------------------------------
# Current organization (tenant)
# ---------------------------------------------------------------------------
async def get_current_org(user: EntitledUser, session: DbSession) -> Organization:
    """Resolve the caller's tenant :class:`Organization` from their SSO principal.

    Depends on :data:`EntitledUser`, so reaching this code already proves the
    caller passed SSO *and* the entitlement gate. The principal's tenant key
    (``org_slug`` from :func:`app.auth.sso._derive_org_slug`, which may carry a
    human slug or a workspace claim) is matched against :attr:`Organization.slug`
    first and then :attr:`Organization.keycloak_group`.

    Fail-closed 403s (never a 404 — the caller is authenticated, the problem is
    that they have no usable tenant here):

    * ``no_organization``     — the principal carries no ``org_slug``.
    * ``org_not_provisioned`` — the slug has no matching org row in this database.

    RLS: once the org is resolved, this dependency calls
    :func:`app.db.rls.set_org_context` to bind the request's DB session to the
    tenant via the ``app.current_org_id`` GUC — every subsequent query in the
    request is then server-side-filtered by the Postgres ``org_isolation``
    policies (migration ``0002_org_rls``). The ``organizations`` slug lookup
    above deliberately runs BEFORE the GUC is set (and ``organizations``
    carries no policy) — the org id isn't known until that query returns. The
    context is session-level so it survives intra-request commits, and is reset
    on request teardown by :func:`app.db.session.get_session`. On sqlite (unit
    tests) the call is a no-op.
    """
    slug = (user.org_slug or "").strip()
    if not slug:
        raise ForbiddenError(
            "no organization is associated with this principal",
            code="no_organization",
            detail={"user_id": user.id},
        )

    org = (
        await session.execute(select(Organization).where(Organization.slug == slug))
    ).scalar_one_or_none()
    if org is None:
        org = (
            await session.execute(
                select(Organization).where(Organization.keycloak_group == slug)
            )
        ).scalar_one_or_none()
    if org is None:
        raise ForbiddenError(
            f"organization {slug!r} is not provisioned in Security-Ops",
            code="org_not_provisioned",
            detail={"org_slug": slug},
        )

    # Bind the request's DB session to this tenant for Postgres RLS filtering
    # (fail-closed second layer beneath the explicit org_id filters).
    await set_org_context(session, org.id)
    return org


#: The calling operator's tenant. Routes compare child rows' ``org_id`` against
#: ``CurrentOrg.id`` for row-level isolation (cross-org access → 404); resolving
#: this dependency also arms Postgres RLS for the request (see above), so the
#: database itself backstops those explicit filters.
CurrentOrg = Annotated[Organization, Depends(get_current_org)]


__all__ = [
    "DbSession",
    "EntitledUser",
    "CurrentOrg",
    "get_current_org",
]
