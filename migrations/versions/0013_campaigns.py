"""campaigns — bounded multi-step autonomous pentest plan tables.

Two tables: ``campaigns`` (the campaign record with budget/phase/status) and
``campaign_runs`` (individual run steps within a campaign). Both carry
``org_id`` for the same fail-closed RLS ``org_isolation`` policy as the other
tenant tables.

Both tables have ``created_at``/``updated_at`` (via TimestampMixin) since
campaign state is mutable — unlike the append-only audit/run_events rows.

Revision ID: 0013_campaigns
Revises: 0012_run_events
Create Date: 2026-07-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0013_campaigns"
down_revision = "0012_run_events"
branch_labels = None
depends_on = None

_JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

# Same fail-closed predicate as the other tenant tables.
_ORG_PREDICATE = "org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid"
_POLICY = "org_isolation"


def upgrade() -> None:
    # -- campaigns table ------------------------------------------------------
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("engagement_id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status",
                  sa.Enum("DRAFT", "ACTIVE", "IN_PROGRESS", "WAITING_APPROVAL",
                          "COMPLETED", "FAILED", "STOPPED", "EXPIRED", "CANCELLED",
                          name="campaign_status"),
                  nullable=False, server_default="DRAFT"),
        sa.Column("current_phase",
                  sa.Enum("RECON", "EXPLOIT", "PRIVILEGE_ESCALATION",
                          "LATERAL_MOVEMENT", "PERSISTENCE", "REPORTING",
                          name="campaign_phase"),
                  nullable=False, server_default="RECON"),
        sa.Column("max_runs", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("max_total_cost_usd", sa.Numeric(14, 6), nullable=False, server_default="500.00"),
        sa.Column("max_duration_hours", sa.Integer(), nullable=False, server_default="72"),
        sa.Column("approval_required_phases", _JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("budget_warning_pct", sa.Integer(), nullable=False, server_default="80"),
        sa.Column("total_runs_launched", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_cost_usd", sa.Numeric(14, 6), nullable=False, server_default="0.00"),
        sa.Column("first_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("phase_state", _JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("resumed_by", sa.Text(), nullable=True),
        sa.Column("resumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("phase_engines", _JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_campaigns"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"],
                                name="fk_campaigns_engagement_id_engagements"),
    )
    op.create_index("ix_campaigns_engagement_id", "campaigns", ["engagement_id"], unique=False)
    op.create_index("ix_campaigns_org_id", "campaigns", ["org_id"], unique=False)
    op.create_index("ix_campaigns_status", "campaigns", ["status"], unique=False)

    # -- campaign_runs table --------------------------------------------------
    op.create_table(
        "campaign_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("campaign_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("phase",
                  sa.Enum("RECON", "EXPLOIT", "PRIVILEGE_ESCALATION",
                          "LATERAL_MOVEMENT", "PERSISTENCE", "REPORTING",
                          name="campaign_phase"),
                  nullable=False),
        sa.Column("status",
                  sa.Enum("PENDING", "IN_PROGRESS", "COMPLETED", "FAILED", "SKIPPED",
                          name="campaign_run_status"),
                  nullable=False, server_default="PENDING"),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("targets", _JSONB, nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cost_usd", sa.Numeric(14, 6), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_campaign_runs"),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"],
                                name="fk_campaign_runs_campaign_id_campaigns"),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"],
                                name="fk_campaign_runs_run_id_runs"),
    )
    op.create_index("ix_campaign_runs_campaign_id", "campaign_runs", ["campaign_id"], unique=False)
    op.create_index("ix_campaign_runs_run_id", "campaign_runs", ["run_id"], unique=False)

    # -- RLS on PostgreSQL ----------------------------------------------------
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in ("campaigns", "campaign_runs"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {_POLICY} ON {table} "
            f"USING ({_ORG_PREDICATE}) "
            f"WITH CHECK ({_ORG_PREDICATE})"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in ("campaign_runs", "campaigns"):
            op.execute(f"DROP POLICY IF EXISTS {_POLICY} ON {table}")
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.drop_table("campaign_runs")
    op.drop_table("campaigns")
    op.execute("DROP TYPE IF EXISTS campaign_run_status")
    op.execute("DROP TYPE IF EXISTS campaign_phase")
    op.execute("DROP TYPE IF EXISTS campaign_status")
