"""finding_triaged_audit — add the FINDING_TRIAGED value to the audit_action enum

Operator finding triage ("Mark verified / false positive / reopen") appends a
``FINDING_TRIAGED`` audit row (see :func:`app.services.findings.set_finding_status`).
On PostgreSQL ``action`` is the NATIVE ``audit_action`` enum type (created in
0001_initial), so a new value must be added to the type with ``ALTER TYPE ... ADD
VALUE`` before any row can carry it — the model change alone is not enough.

Transaction handling: this env.py runs each migration INSIDE a transaction
(``env.py`` wraps ``context.run_migrations()`` in ``context.begin_transaction()``).
On PostgreSQL, ``ALTER TYPE ... ADD VALUE`` cannot run inside a transaction block
on older/some server versions, so the ``ADD VALUE`` is issued inside an
``op.get_context().autocommit_block()`` which commits the surrounding transaction
and runs the statement in its own autocommit context. ``IF NOT EXISTS`` keeps it
idempotent/re-runnable.

Non-PostgreSQL (e.g. the SQLite test suite) stores the enum as a VARCHAR/CHECK
generated from the model, so the model change alone suffices and this migration is
a guarded no-op there.

downgrade: no-op. PostgreSQL cannot DROP a value from an enum type, and nothing
references the value once the app is rolled back, so removal is neither possible
nor necessary.

Revision ID: 0005_finding_triaged_audit
Revises: 0004_run_queue
Create Date: 2026-07-06
"""

from __future__ import annotations

from alembic import op


# revision identifiers, used by Alembic.
revision = "0005_finding_triaged_audit"
down_revision = "0004_run_queue"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PostgreSQL-only: the native audit_action enum needs the new value added.
    # SQLite (tests) derives the enum from the model — nothing to alter.
    if op.get_bind().dialect.name != "postgresql":
        return
    # ALTER TYPE ... ADD VALUE cannot run inside a transaction on some PG versions;
    # run it in its own autocommit context. IF NOT EXISTS makes it idempotent.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'FINDING_TRIAGED'")


def downgrade() -> None:
    # No-op: PostgreSQL cannot drop a value from an enum type, and removal is
    # unnecessary once the app that emits FINDING_TRIAGED is rolled back.
    pass
