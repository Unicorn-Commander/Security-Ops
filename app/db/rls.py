"""Org-level Postgres row-level security (RLS) context helpers (spec §5, §10).

Cross-tenant data leakage is a GA blocker, so tenant isolation is enforced in
TWO independent layers:

1. App layer — every business route resolves :data:`app.api.deps.CurrentOrg`
   and repositories filter/compare ``org_id`` explicitly.
2. Database layer (this module + migration ``0002_org_rls``) — Postgres RLS
   policies on the sensitive child tables (``authorized_targets``,
   ``engagements``, ``runs``, ``findings``, ``audit_events``) keyed on the
   session GUC ``app.current_org_id``. Even a buggy or missing app-layer filter
   cannot return another org's rows: with no (or a foreign) GUC the policy
   predicate ``org_id = <guc>::uuid`` is never true — **fail-closed**.

``organizations`` itself deliberately carries NO restrictive policy:
``get_current_org`` must look the org up by slug BEFORE the org id is known
(the bootstrapping problem), and leaking org *names* is far lower risk than
findings; the app-layer slug match already scopes that lookup.

Dependency direction: this module sits below ``app.api.deps`` (which calls
:func:`set_org_context` once per request after tenant resolution) and is
imported lazily by ``app.db.session`` (which calls :func:`clear_org_context`
when the request session winds down). It imports only SQLAlchemy — never the
models, deps, or services — so no cycle is possible.

Transaction/GUC caveat (the subtle part): the GUC is set with
``set_config(..., is_local => false)`` — **session-level, NOT transaction-local**.
Services commit mid-request; a ``SET LOCAL`` (``is_local => true``) would be
silently discarded at the first ``COMMIT`` and every later query in the request
would see zero rows. The flip side of a session-level GUC is that it outlives
the request on the pooled DB connection, so :func:`clear_org_context` must run
when the request session is torn down (wired into
``app.db.session.get_session``'s ``finally``) to keep one tenant's context from
bleeding into the next request that borrows the connection.

Both helpers are dialect-guarded no-ops off Postgres: sqlite (the unit-test DB)
has no ``set_config``, and there are no RLS policies there anyway.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

#: The Postgres session GUC the ``org_isolation`` policies key on
#: (see migration ``0002_org_rls``).
ORG_GUC = "app.current_org_id"


def is_postgres_session(session: AsyncSession) -> bool:
    """True when the session is bound to a PostgreSQL engine.

    RLS + ``set_config`` exist only on Postgres; on sqlite (unit tests) both
    helpers must be safe no-ops so the default suite runs container-free.
    Public because ``app.db.session.get_session`` uses it to decide whether the
    teardown reset (rollback → clear → commit) is needed at all.
    """
    bind = session.get_bind()
    return bind is not None and bind.dialect.name == "postgresql"


async def set_org_context(session: AsyncSession, org_id: uuid.UUID) -> None:
    """Bind ``session``'s DB connection to one tenant for RLS filtering.

    Called by ``app.api.deps.get_current_org`` immediately after the caller's
    :class:`~app.models.organization.Organization` is resolved, so every
    subsequent query in the request is server-side-filtered to that org.

    Uses ``is_local => false`` (session-level) deliberately — see the module
    docstring: a transaction-local ``SET LOCAL`` would be lost at the first
    intra-request commit and silently hide all rows afterwards.
    """
    if not is_postgres_session(session):
        return
    await session.execute(
        text(f"SELECT set_config('{ORG_GUC}', :org_id, false)"),
        {"org_id": str(org_id)},
    )


async def clear_org_context(session: AsyncSession) -> None:
    """Reset the org GUC so a pooled connection never leaks tenant context.

    Sets the GUC to ``''`` (the policies coerce the empty string to NULL via
    ``NULLIF``, so the predicate is never true → rows invisible, fail-closed).
    Wired into ``app.db.session.get_session``'s ``finally`` so it runs on every
    request teardown, success or failure.
    """
    if not is_postgres_session(session):
        return
    await session.execute(text(f"SELECT set_config('{ORG_GUC}', '', false)"))


__all__ = ["ORG_GUC", "is_postgres_session", "set_org_context", "clear_org_context"]
