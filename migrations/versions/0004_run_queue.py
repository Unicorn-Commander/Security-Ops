"""run_queue — dispatch hand-off from the API to the isolated runner sidecar

Adds the ``run_queue`` table (see :mod:`app.models.run_queue`). When
``settings.run_dispatch_mode == "queue"``, ``app.services.runs.start_run`` inserts
one row here IN THE SAME TRANSACTION as the gate-cleared PENDING run, so dispatch
is atomic and durable. The dedicated ``secops-runner`` sidecar claims the oldest
unclaimed row (``FOR UPDATE SKIP LOCKED``) and executes it — the internet-facing
API never spawns Strix and never mounts the Docker socket.

RLS: this table deliberately gets NO ``org_isolation`` policy. Like
``organizations`` and ``personal_access_tokens``, it is read by the runner as
``secops_app`` with NO ``app.current_org_id`` GUC set (the runner has no request
context); an unpoliced table is visible to that NOBYPASSRLS role. It holds only
routing metadata (run/org/engagement ids + scope params), never findings/evidence
— those stay under RLS, accessed via ``execute_run`` with the org GUC bound.

Revision ID: 0004_run_queue
Revises: 0003_personal_access_tokens
Create Date: 2026-07-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "0004_run_queue"
down_revision = "0003_personal_access_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_queue",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope_mode", sa.Text(), nullable=True),
        sa.Column("diff_base", sa.Text(), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_by", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_run_queue"),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], name="fk_run_queue_run_id_runs"),
        sa.UniqueConstraint("run_id", name="uq_run_queue_run_id"),
    )
    op.create_index("ix_run_queue_run_id", "run_queue", ["run_id"], unique=False)
    # The claim query orders available (claimed_at IS NULL) rows oldest-first.
    op.create_index("ix_run_queue_claimed_at", "run_queue", ["claimed_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_run_queue_claimed_at", table_name="run_queue")
    op.drop_index("ix_run_queue_run_id", table_name="run_queue")
    op.drop_table("run_queue")
