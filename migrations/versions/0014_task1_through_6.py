"""Abuse controls, engine domains, reports infra, remediation, scheduled scans.

Covers Tasks 1–6:

- **Abuse controls (Task 1):** add ``max_concurrent_runs``, ``rate_limit_rpm``,
  ``max_run_duration_seconds``, ``engine_domain_restrictions`` to
  ``organizations``; add ``max_execution_time`` to ``runs``.
- **Engine domains (Task 2):** add ``engine_domain_restrictions`` to
  ``engagements``.
- **Client reports (Task 3):** report infra (renderers, templates) — no schema
  change.
- **Remediation workflow (Task 4):** create ``finding_remediations`` table.
- **Scheduled scans (Task 5):** create ``scheduled_scans`` table.
- **Prowler credential minting (Task 6):** engine change — no schema change.

Revision ID: 0014_task1_through_6
Revises: 0013_campaigns
Create Date: 2026-07-14

The live host already has this revision applied, and some environments create
tables from ``Base.metadata`` before running Alembic. The upgrade therefore
reconciles missing columns/tables/indexes instead of issuing unconditional DDL.
That keeps a 0013 database migratable while making a repeated upgrade safe.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0014_task1_through_6"
down_revision = "0013_campaigns"
branch_labels = None
depends_on = None

_JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

# Same fail-closed RLS predicate as the other tenant tables.
_ORG_PREDICATE = (
    "org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid"
)
_POLICY = "org_isolation"
_RE_TEST_VALUES = ("PENDING", "FIXED", "REOPENED", "NOT_REQUIRED")


def _bind():
    return op.get_bind()


def _has_table(table_name: str) -> bool:
    return table_name in sa.inspect(_bind()).get_table_names()


def _column_names(table_name: str) -> set[str]:
    if not _has_table(table_name):
        return set()
    return {column["name"] for column in sa.inspect(_bind()).get_columns(table_name)}


def _add_missing_columns(table_name: str, columns: list[sa.Column]) -> None:
    """Add only columns absent from an existing table."""
    existing = _column_names(table_name)
    for column in columns:
        if column.name not in existing:
            op.add_column(table_name, column)
            existing.add(column.name)


def _create_index_if_missing(
    name: str, table_name: str, columns: list[str], *, unique: bool = False
) -> None:
    if not _has_table(table_name):
        return
    indexes = sa.inspect(_bind()).get_indexes(table_name)
    if not any(index.get("name") == name for index in indexes):
        op.create_index(name, table_name, columns, unique=unique)


def _ensure_re_test_status_type() -> None:
    """Create the PostgreSQL enum once, tolerating a pre-existing type."""
    if _bind().dialect.name != "postgresql":
        return
    enum = postgresql.ENUM(*_RE_TEST_VALUES, name="re_test_status")
    enum.create(_bind(), checkfirst=True)


def _re_test_status_type():
    if _bind().dialect.name == "postgresql":
        return postgresql.ENUM(
            *_RE_TEST_VALUES,
            name="re_test_status",
            create_type=False,
        )
    return sa.Enum(*_RE_TEST_VALUES, name="re_test_status")


def upgrade() -> None:
    _add_columns()
    _create_finding_remediations()
    _create_scheduled_scans()
    _apply_rls()


def _add_columns() -> None:
    # -- organizations ---------------------------------------------------------
    _add_missing_columns(
        "organizations",
        [
            sa.Column("max_concurrent_runs", sa.Integer(), nullable=True),
            sa.Column("rate_limit_rpm", sa.Integer(), nullable=True),
            sa.Column("max_run_duration_seconds", sa.Integer(), nullable=True),
            sa.Column("engine_domain_restrictions", _JSONB, nullable=True),
        ],
    )

    # -- engagements -----------------------------------------------------------
    _add_missing_columns(
        "engagements",
        [sa.Column("engine_domain_restrictions", _JSONB, nullable=True)],
    )

    # -- runs ------------------------------------------------------------------
    _add_missing_columns(
        "runs",
        [sa.Column("max_execution_time", sa.Integer(), nullable=True)],
    )


def _finding_remediation_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("remediation_plan", sa.Text(), nullable=True),
        sa.Column("remediation_steps", _JSONB, nullable=True),
        sa.Column("assigned_to", sa.String(length=255), nullable=True),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "re_test_status",
            _re_test_status_type(),
            nullable=False,
            server_default="PENDING",
        ),
        sa.Column("re_test_evidence", sa.Text(), nullable=True),
        sa.Column("remediation_notes", sa.Text(), nullable=True),
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
    ]


def _create_finding_remediations() -> None:
    columns = _finding_remediation_columns()
    if not _has_table("finding_remediations"):
        _ensure_re_test_status_type()
        op.create_table(
            "finding_remediations",
            *columns,
            sa.PrimaryKeyConstraint("id", name="pk_finding_remediations"),
            sa.ForeignKeyConstraint(
                ["finding_id"],
                ["findings.id"],
                name="fk_finding_remediations_finding_id_findings",
            ),
            sa.UniqueConstraint(
                "finding_id", name="uq_finding_remediations_finding_id"
            ),
        )
    else:
        if "re_test_status" not in _column_names("finding_remediations"):
            _ensure_re_test_status_type()
        _add_missing_columns("finding_remediations", columns)
    _create_index_if_missing(
        "ix_finding_remediations_finding_id",
        "finding_remediations",
        ["finding_id"],
        unique=True,
    )


def _scheduled_scan_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("engagement_id", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("cron_expression", sa.String(length=128), nullable=False),
        sa.Column("targets", _JSONB, nullable=False),
        sa.Column("engine", sa.String(length=64), nullable=True),
        sa.Column("model_profile", sa.String(length=255), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
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
    ]


def _create_scheduled_scans() -> None:
    columns = _scheduled_scan_columns()
    if not _has_table("scheduled_scans"):
        op.create_table(
            "scheduled_scans",
            *columns,
            sa.PrimaryKeyConstraint("id", name="pk_scheduled_scans"),
            sa.ForeignKeyConstraint(
                ["org_id"],
                ["organizations.id"],
                name="fk_scheduled_scans_org_id_organizations",
            ),
            sa.ForeignKeyConstraint(
                ["engagement_id"],
                ["engagements.id"],
                name="fk_scheduled_scans_engagement_id_engagements",
            ),
        )
    else:
        _add_missing_columns("scheduled_scans", columns)
    _create_index_if_missing("ix_scheduled_scans_org_id", "scheduled_scans", ["org_id"])


def _apply_rls() -> None:
    if _bind().dialect.name != "postgresql":
        return
    op.execute("ALTER TABLE scheduled_scans ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE scheduled_scans FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_policies
                WHERE schemaname = current_schema()
                  AND tablename = 'scheduled_scans'
                  AND policyname = 'org_isolation'
            ) THEN
                CREATE POLICY org_isolation ON scheduled_scans
                USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
                WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);
            END IF;
        END
        $$;
        """
    )


def _drop_columns_if_present(table_name: str, column_names: list[str]) -> None:
    existing = _column_names(table_name)
    for column_name in column_names:
        if column_name in existing:
            op.drop_column(table_name, column_name)


def downgrade() -> None:
    if _bind().dialect.name == "postgresql" and _has_table("scheduled_scans"):
        op.execute("DROP POLICY IF EXISTS org_isolation ON scheduled_scans")
        op.execute("ALTER TABLE scheduled_scans NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE scheduled_scans DISABLE ROW LEVEL SECURITY")

    if _has_table("scheduled_scans"):
        op.drop_table("scheduled_scans")
    if _has_table("finding_remediations"):
        op.drop_table("finding_remediations")

    _drop_columns_if_present("runs", ["max_execution_time"])
    _drop_columns_if_present("engagements", ["engine_domain_restrictions"])
    _drop_columns_if_present(
        "organizations",
        [
            "engine_domain_restrictions",
            "max_run_duration_seconds",
            "rate_limit_rpm",
            "max_concurrent_runs",
        ],
    )

    if _bind().dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS re_test_status")
