"""org-level row-level security — policies on the five sensitive child tables

Phase 3 pulled forward (spec §5, §10): cross-tenant data leakage is a GA
blocker, so tenant isolation gets a second, database-enforced layer beneath the
app-layer ``org_id`` filtering. Each sensitive child table gets:

* ``ENABLE ROW LEVEL SECURITY``  — policies apply to non-owner roles.
* ``FORCE ROW LEVEL SECURITY``   — policies apply to the table OWNER too. This
  matters: the app may connect as the owning role, and without FORCE the owner
  silently bypasses every policy.
* one ``org_isolation`` policy (both USING and WITH CHECK) keyed on the session
  GUC ``app.current_org_id`` set per-request by ``app.db.rls.set_org_context``.

Fail-closed by construction: ``current_setting('app.current_org_id', true)``
returns NULL when the GUC was never set (the second arg means "missing → NULL,
not error"), and ``NULLIF(..., '')`` maps the cleared-out value written by
``app.db.rls.clear_org_context`` (empty string) to NULL as well — without the
NULLIF, ``''::uuid`` would raise instead of hiding rows. Either way the
predicate ``org_id = NULL`` is never true, so with no org context ZERO rows are
visible or writable.

``organizations`` deliberately gets NO policy: ``app.api.deps.get_current_org``
must resolve the org by slug BEFORE the org id (and hence the GUC) is known —
the bootstrapping problem. Leaking org names is far lower risk than findings,
and the app-layer slug match already scopes that lookup.

``audit_events.org_id`` is nullable: rows with a NULL ``org_id`` (system-level
events recorded without org context) are invisible under this policy for every
tenant. That is deliberate and acceptable — org-less audit rows are admin-only,
to be read via a privileged/BYPASSRLS channel, never through tenant sessions.

NOTE (superuser/BYPASSRLS): roles with the BYPASSRLS attribute or superusers
are exempt from RLS regardless of FORCE. The app's runtime role must be neither.

Dialect guard: the whole migration is PostgreSQL-only. On sqlite (the unit-test
DB) both upgrade and downgrade are clean no-ops so ``alembic upgrade head``
works on either backend.

Revision ID: 0002_org_rls
Revises: 0001_initial
Create Date: 2026-07-05
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "0002_org_rls"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


#: The strict tenant tables (all carry a NON-NULL ``org_id``). Reads AND writes
#: are both confined to the current org. ``organizations`` is intentionally
#: absent — see module docstring (slug-lookup bootstrapping).
RLS_TABLES = (
    "authorized_targets",
    "engagements",
    "runs",
    "findings",
)

#: ``audit_events`` is handled separately: its ``org_id`` is NULLABLE (system /
#: entitlement / engagement-not-found events are recorded WITHOUT an org, and
#: some are written before the request's org context exists). It therefore gets a
#: NULL-tolerant WITH CHECK so those legitimate append-only rows are never
#: rejected, while its USING (read) filter stays strict so a tenant still sees
#: only its own org's audit trail (org-less system rows are admin/BYPASSRLS-only).
AUDIT_TABLE = "audit_events"

POLICY_NAME = "org_isolation"

#: The strict predicate for reads (and for writes on the strict tables).
#: ``current_setting(..., true)`` → NULL when the GUC is unset; ``NULLIF(.., '')``
#: → NULL when it was cleared to '' — both fail closed (no rows), never error.
_ORG_PREDICATE = (
    "org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid"
)

#: Write predicate for audit_events: the row must belong to the current org OR be
#: an org-less system row. This never lets a tenant forge ANOTHER org's audit row
#: (org_id must equal the GUC when non-null), only permits NULL-org system events.
_AUDIT_WRITE_PREDICATE = f"({_ORG_PREDICATE}) OR org_id IS NULL"


def _upgrade_statements() -> list[str]:
    """The exact DDL applied on Postgres, one statement per string.

    Exposed as a helper (rather than inlined in ``upgrade``) so the
    ``tests/test_rls_postgres.py`` integration test can apply the identical DDL
    to a scratch database without drift.
    """
    statements: list[str] = []
    for table in RLS_TABLES:
        statements.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        statements.append(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        statements.append(
            f"CREATE POLICY {POLICY_NAME} ON {table} "
            f"USING ({_ORG_PREDICATE}) "
            f"WITH CHECK ({_ORG_PREDICATE})"
        )
    # audit_events: strict reads, NULL-tolerant appends (see AUDIT_TABLE note).
    statements.append(f"ALTER TABLE {AUDIT_TABLE} ENABLE ROW LEVEL SECURITY")
    statements.append(f"ALTER TABLE {AUDIT_TABLE} FORCE ROW LEVEL SECURITY")
    statements.append(
        f"CREATE POLICY {POLICY_NAME} ON {AUDIT_TABLE} "
        f"USING ({_ORG_PREDICATE}) "
        f"WITH CHECK ({_AUDIT_WRITE_PREDICATE})"
    )
    return statements


def _downgrade_statements() -> list[str]:
    """Reverse DDL: drop each policy and switch RLS back off."""
    statements: list[str] = []
    for table in (AUDIT_TABLE, *reversed(RLS_TABLES)):
        statements.append(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
        statements.append(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        statements.append(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    return statements


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return  # RLS is a Postgres feature; no-op on sqlite (unit-test DB).
    for statement in _upgrade_statements():
        op.execute(statement)


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for statement in _downgrade_statements():
        op.execute(statement)
