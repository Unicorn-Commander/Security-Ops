"""finding_fingerprint — add a cross-engine dedup fingerprint to findings.

The fingerprint is a stable SHA-256 hex digest of the engine + CWE/CVE + endpoint +
title tuple. It lets the repository de-duplicate the same issue when multiple engines
or repeated runs surface it again within one engagement.

Revision ID: 0010_finding_fingerprint
Revises: 0009_cloud_account_target
Create Date: 2026-07-09
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0010_finding_fingerprint"
down_revision = "0009_cloud_account_target"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("fingerprint", sa.String(length=64), nullable=True))
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_column("findings", "fingerprint")
