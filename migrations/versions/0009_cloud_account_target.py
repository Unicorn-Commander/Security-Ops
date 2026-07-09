"""cloud_account_target — add CLOUD_ACCOUNT target kind + CLOUD_ROLE attestation method

Engine #5 (Prowler, CSPM) introduces a new target kind — a cloud account / project /
subscription (``aws:<account-id>`` / ``gcp:<project-id>`` / ``azure:<subscription>``) —
and a new attestation method, ``CLOUD_ROLE``: a possession proof where the operator
grants Security-Ops' scanner principal a scoped cross-account role whose trust policy
requires our per-target external ID, and the server proves authorization by assuming it
(STS AssumeRole). See ``app/authz/cloud_proof.py`` and ``app/engine/prowler_runner.py``.

On PostgreSQL ``target_kind`` and ``attestation_method`` are NATIVE enum types (created
in 0001_initial), so each new label must be added with ``ALTER TYPE ... ADD VALUE``
before any row can carry it — the model change alone is not enough. ``ADD VALUE`` cannot
run inside a transaction on some PG versions and this env.py wraps each migration in one,
so the statements run inside ``op.get_context().autocommit_block()``; ``IF NOT EXISTS``
keeps them idempotent / re-runnable (mirrors 0006_break_glass_attestation and
0008_target_kind_image).

Non-PostgreSQL (the SQLite test suite) stores the enums as VARCHAR generated from the
model, so the model change alone suffices and this migration is a guarded no-op.

downgrade: no-op. PostgreSQL cannot DROP a value from an enum type, and nothing
references the values once the app is rolled back.

Revision ID: 0009_cloud_account_target
Revises: 0008_target_kind_image
Create Date: 2026-07-09
"""

from __future__ import annotations

from alembic import op


# revision identifiers, used by Alembic.
revision = "0009_cloud_account_target"
down_revision = "0008_target_kind_image"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PostgreSQL-only: the native enums need the new values added. SQLite (tests)
    # derives the enums from the model — nothing to alter.
    if op.get_bind().dialect.name != "postgresql":
        return
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE target_kind ADD VALUE IF NOT EXISTS 'CLOUD_ACCOUNT'")
        op.execute("ALTER TYPE attestation_method ADD VALUE IF NOT EXISTS 'CLOUD_ROLE'")


def downgrade() -> None:
    # No-op: PostgreSQL cannot drop a value from an enum type, and removal is
    # unnecessary once the app that emits these values is rolled back.
    pass
