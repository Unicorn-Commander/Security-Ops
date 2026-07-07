"""target_kind_image — add the ``IMAGE`` value to the ``target_kind`` enum

Engine #4 (Trivy) introduces a new target kind: a container image reference
(``registry/name:tag`` / digest), scanned by ``trivy image``. Trivy also scans
repositories (the existing ``REPO`` kind, via ``trivy fs`` / ``trivy repo``), so
this migration only needs to add the single new ``IMAGE`` label.

On PostgreSQL ``target_kind`` is a NATIVE enum type (created in 0001_initial), so a
new label must be added with ``ALTER TYPE ... ADD VALUE`` before any row can carry
it — the model change alone is not enough. ``ADD VALUE`` cannot run inside a
transaction on some PG versions and this env.py wraps each migration in one, so the
statement runs inside ``op.get_context().autocommit_block()``; ``IF NOT EXISTS``
keeps it idempotent / re-runnable (mirrors 0006_break_glass_attestation).

Non-PostgreSQL (the SQLite test suite) stores the enum as VARCHAR generated from
the model, so the model change alone suffices and this migration is a guarded no-op.

downgrade: no-op. PostgreSQL cannot DROP a value from an enum type, and nothing
references the value once the app is rolled back.

Revision ID: 0008_target_kind_image
Revises: 0007_run_engine
Create Date: 2026-07-07
"""

from __future__ import annotations

from alembic import op


# revision identifiers, used by Alembic.
revision = "0008_target_kind_image"
down_revision = "0007_run_engine"
branch_labels = None
depends_on = None


_NEW_TARGET_KINDS = ("IMAGE",)


def upgrade() -> None:
    # PostgreSQL-only: the native enum needs the new value added. SQLite (tests)
    # derives the enum from the model — nothing to alter.
    if op.get_bind().dialect.name != "postgresql":
        return
    with op.get_context().autocommit_block():
        for value in _NEW_TARGET_KINDS:
            op.execute(f"ALTER TYPE target_kind ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    # No-op: PostgreSQL cannot drop a value from an enum type, and removal is
    # unnecessary once the app that emits this value is rolled back.
    pass
