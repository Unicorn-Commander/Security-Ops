"""initial schema — organizations, authorized_targets, engagements, runs, findings, audit_events

Phase 1 (spec §5): the six core tables with their enums, FKs, JSONB columns, and
unique/index constraints, named per the ``app.db.base.Base`` naming_convention so
Alembic autogenerate stays clean. Org-level Postgres RLS policies and the
audit_events append-only UPDATE/DELETE trigger are a deliberate Phase 3 follow-up
migration (spec §5, §10) — NOT created here.

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


# --- Native Postgres enum types -------------------------------------------------
# create_type=False: we create/drop them explicitly (below) so table creation does
# not implicitly emit CREATE TYPE and downgrade cleans them up.
target_kind = postgresql.ENUM(
    "DOMAIN", "URL", "IP_RANGE", "REPO", name="target_kind", create_type=False
)
attestation_method = postgresql.ENUM(
    "CHECKBOX", "TYPED_CONFIRMATION", "DNS_TXT", "FILE_DROP", "HTTP_HEADER", "OWNED",
    name="attestation_method", create_type=False,
)
attestation_status = postgresql.ENUM(
    "UNATTESTED", "ATTESTED", "EXPIRED", "REVOKED",
    name="attestation_status", create_type=False,
)
engagement_status = postgresql.ENUM(
    "DRAFT", "ACTIVE", "PAUSED", "COMPLETED", "STOPPED", "EXPIRED",
    name="engagement_status", create_type=False,
)
run_status = postgresql.ENUM(
    "PENDING", "RUNNING", "STOPPED", "COMPLETED", "FAILED", "DENIED",
    name="run_status", create_type=False,
)
run_mode = postgresql.ENUM("QUICK", "STANDARD", "DEEP", name="run_mode", create_type=False)
finding_severity = postgresql.ENUM(
    "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="finding_severity", create_type=False
)
finding_status = postgresql.ENUM(
    "NEW", "VERIFIED", "FALSE_POSITIVE", "HANDED_OFF", "REMEDIATED",
    name="finding_status", create_type=False,
)
audit_action = postgresql.ENUM(
    "ENGAGEMENT_CREATED", "ENGAGEMENT_ACTIVATED", "TARGET_REGISTERED", "TARGET_ATTESTED",
    "TARGET_REVOKED", "SCOPE_CHECK_ALLOWED", "SCOPE_CHECK_DENIED", "RUN_STARTED",
    "RUN_STOPPED", "RUN_COMPLETED", "FINDING_RECORDED", "FINDING_HANDOFF",
    "EMERGENCY_STOP", "ENTITLEMENT_DENIED", name="audit_action", create_type=False,
)

_ALL_ENUMS = (
    target_kind, attestation_method, attestation_status, engagement_status,
    run_status, run_mode, finding_severity, finding_status, audit_action,
)


def upgrade() -> None:
    bind = op.get_bind()
    for enum_type in _ALL_ENUMS:
        enum_type.create(bind, checkfirst=True)

    # --- organizations (tenant root) ---------------------------------------
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("keycloak_group", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_organizations"),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    # --- authorized_targets (the gate's registry) --------------------------
    op.create_table(
        "authorized_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", target_kind, nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("label", sa.Text(), nullable=True),
        sa.Column("owner_principal", sa.Text(), nullable=True),
        sa.Column("attestation_status", attestation_status, nullable=False, server_default="UNATTESTED"),
        sa.Column("attestation_method", attestation_method, nullable=True),
        sa.Column("attested_by", sa.Text(), nullable=True),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attestation_evidence", postgresql.JSONB(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_authorized_targets"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name="fk_authorized_targets_org_id_organizations"
        ),
        sa.UniqueConstraint("org_id", "kind", "value", name="uq_authorized_targets_org_id"),
    )
    op.create_index("ix_authorized_targets_org_id", "authorized_targets", ["org_id"], unique=False)

    # --- engagements (scope-of-engagement) ---------------------------------
    op.create_table(
        "engagements",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("status", engagement_status, nullable=False, server_default="DRAFT"),
        sa.Column("scope", postgresql.JSONB(), nullable=False),
        sa.Column("rules_of_engagement", postgresql.JSONB(), nullable=False),
        sa.Column(
            "model_profile", sa.String(length=255), nullable=False,
            server_default="hybrid-local-sweep-verify",
        ),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("emergency_stopped", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_engagements"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name="fk_engagements_org_id_organizations"
        ),
    )
    op.create_index("ix_engagements_org_id", "engagements", ["org_id"], unique=False)

    # --- runs (created only after the gate passes) -------------------------
    op.create_table(
        "runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("strix_run_id", sa.Text(), nullable=True),
        sa.Column("mode", run_mode, nullable=False),
        sa.Column("model_profile", sa.String(length=255), nullable=False),
        sa.Column("targets", postgresql.JSONB(), nullable=False),
        sa.Column("status", run_status, nullable=False, server_default="PENDING"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cost_usd", sa.Numeric(precision=14, scale=6), nullable=True),
        sa.Column("usage", postgresql.JSONB(), nullable=True),
        sa.Column("report_path", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_runs"),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["engagements.id"], name="fk_runs_engagement_id_engagements"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name="fk_runs_org_id_organizations"
        ),
    )
    op.create_index("ix_runs_engagement_id", "runs", ["engagement_id"], unique=False)

    # --- findings (populated by the Phase 2 runner) ------------------------
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", finding_severity, nullable=False),
        sa.Column("cwe", sa.String(length=64), nullable=True),
        sa.Column("endpoint", sa.Text(), nullable=True),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column("poc", sa.Text(), nullable=True),
        sa.Column("verified_by", sa.Text(), nullable=True),
        sa.Column("status", finding_status, nullable=False, server_default="NEW"),
        sa.Column("handoff_ref", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], name="fk_findings_run_id_runs"),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["engagements.id"], name="fk_findings_engagement_id_engagements"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name="fk_findings_org_id_organizations"
        ),
    )
    op.create_index("ix_findings_run_id", "findings", ["run_id"], unique=False)

    # --- audit_events (append-only, hash-chained, NO foreign keys) ---------
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", audit_action, nullable=False),
        sa.Column("actor_id", sa.Text(), nullable=False),
        sa.Column("actor_email", sa.Text(), nullable=True),
        sa.Column("target", sa.Text(), nullable=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("decision", sa.String(length=16), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        sa.Column("prev_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
        sa.UniqueConstraint("event_hash", name="uq_audit_events_event_hash"),
    )
    op.create_index("ix_audit_events_org_id", "audit_events", ["org_id"], unique=False)
    op.create_index("ix_audit_events_engagement_id", "audit_events", ["engagement_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_events_engagement_id", table_name="audit_events")
    op.drop_index("ix_audit_events_org_id", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index("ix_findings_run_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_runs_engagement_id", table_name="runs")
    op.drop_table("runs")

    op.drop_index("ix_engagements_org_id", table_name="engagements")
    op.drop_table("engagements")

    op.drop_index("ix_authorized_targets_org_id", table_name="authorized_targets")
    op.drop_table("authorized_targets")

    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_table("organizations")

    bind = op.get_bind()
    for enum_type in reversed(_ALL_ENUMS):
        enum_type.drop(bind, checkfirst=True)
