"""run_engine — add the ``engine`` column to ``runs`` (additive multi-engine)

Adds a plain ``VARCHAR(32) NOT NULL DEFAULT 'strix'`` column so a run records which
scan engine executed it (``strix`` = autonomous agent, ``nuclei`` = templated
breadth scanner). Deliberately a string, not an enum, so future engines need no
migration. The server default backfills every existing row to ``strix`` (the only
engine before this), so the change is non-breaking on a populated table.

Revision ID: 0007_run_engine
Revises: 0006_break_glass_attestation
Create Date: 2026-07-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0007_run_engine"
down_revision = "0006_break_glass_attestation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column("engine", sa.String(length=32), nullable=False, server_default="strix"),
    )


def downgrade() -> None:
    op.drop_column("runs", "engine")
