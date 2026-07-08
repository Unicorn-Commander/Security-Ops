"""break_glass_attestation — admin-only SELF_ATTESTED / BREAK_GLASS methods + audit

Adds the two admin-only "authorized-operator" attestation methods (spec §4
break-glass extension) to the native ``attestation_method`` enum, and the
dedicated ``TARGET_BREAK_GLASS`` value to the ``audit_action`` enum so every
break-glass grant is independently alertable.

On PostgreSQL both enums are NATIVE types (created in 0001_initial), so new labels
must be added with ``ALTER TYPE ... ADD VALUE`` before any row can carry them — the
model change alone is not enough. ``ADD VALUE`` cannot run inside a transaction on
some PG versions and this env.py wraps each migration in one, so the statements run
inside ``op.get_context().autocommit_block()``. ``IF NOT EXISTS`` keeps it
idempotent / re-runnable.

Non-PostgreSQL (the SQLite test suite) stores these enums as VARCHAR generated from
the model, so the model change alone suffices and this migration is a guarded no-op.

downgrade: no-op. PostgreSQL cannot DROP a value from an enum type, and nothing
references the values once the app is rolled back.

Revision ID: 0006_break_glass_attestation
Revises: 0005_finding_triaged_audit
Create Date: 2026-07-07
"""

from __future__ import annotations

from alembic import op


# revision identifiers, used by Alembic.
revision = "0006_break_glass_attestation"
down_revision = "0005_finding_triaged_audit"
branch_labels = None
depends_on = None


_NEW_ATTESTATION_METHODS = ("SELF_ATTESTED", "BREAK_GLASS")
_NEW_AUDIT_ACTIONS = ("TARGET_BREAK_GLASS",)


def upgrade() -> None:
    # PostgreSQL-only: the native enums need the new values added. SQLite (tests)
    # derives the enum from the model — nothing to alter.
    if op.get_bind().dialect.name != "postgresql":
        return
    with op.get_context().autocommit_block():
        for value in _NEW_ATTESTATION_METHODS:
            op.execute(f"ALTER TYPE attestation_method ADD VALUE IF NOT EXISTS '{value}'")
        for value in _NEW_AUDIT_ACTIONS:
            op.execute(f"ALTER TYPE audit_action ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    # No-op: PostgreSQL cannot drop a value from an enum type, and removal is
    # unnecessary once the app that emits these values is rolled back.
    pass
