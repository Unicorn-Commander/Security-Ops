"""finding_closure — add closure metadata to findings.

Closed findings now capture the operator-provided reason plus who/when closed them.

Revision ID: 0011_finding_closure
Revises: 0010_finding_fingerprint
Create Date: 2026-07-09
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0011_finding_closure"
down_revision = "0010_finding_fingerprint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("closure_reason", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("closed_by", sa.String(length=255), nullable=True))
    op.add_column(
        "findings", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("findings", "closed_at")
    op.drop_column("findings", "closed_by")
    op.drop_column("findings", "closure_reason")
