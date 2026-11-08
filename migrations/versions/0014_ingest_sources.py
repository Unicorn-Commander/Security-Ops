"""Organization-scoped Center Deep webhook credentials.

The receiver discovers the tenant by trying enabled sources under each normal
``app.current_org_id`` context.  The organization bootstrap table is intentionally
not RLS-protected, while this source table uses the same fail-closed policy as
the other tenant tables; no receiver-specific RLS bypass is added.

Revision ID: 0014_ingest_sources
Revises: 0014_task1_through_6
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_ingest_sources"
down_revision = "0014_task1_through_6"
branch_labels = None
depends_on = None

_ORG_PREDICATE = (
    "org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid"
)
_POLICY = "org_isolation"


def upgrade() -> None:
    op.create_table(
        "ingest_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "kind",
            sa.String(length=64),
            nullable=False,
            server_default="center-deep",
        ),
        sa.Column("secret", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_webhook_id", sa.String(length=255), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_ingest_sources"),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name="fk_ingest_sources_org_id_organizations",
        ),
    )
    op.create_index("ix_ingest_sources_org_id", "ingest_sources", ["org_id"])

    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("ALTER TABLE ingest_sources ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ingest_sources FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY {_POLICY} ON ingest_sources "
        f"USING ({_ORG_PREDICATE}) "
        f"WITH CHECK ({_ORG_PREDICATE})"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"DROP POLICY IF EXISTS {_POLICY} ON ingest_sources")
        op.execute("ALTER TABLE ingest_sources NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE ingest_sources DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_ingest_sources_org_id", table_name="ingest_sources")
    op.drop_table("ingest_sources")
