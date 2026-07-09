"""run_events — the append-only per-run live activity stream (SSE step log).

Backs ``GET /runs/{id}/events``: the runner appends one row per lifecycle step
(dispatched / running / engine-spawned / reasoning / finding / verify / terminal)
and the console SSE endpoint replays them in ``seq`` order then tails new rows.

Two parts, mirroring ``runs``/``findings``:

* the table itself (append-only: ``created_at`` only, no ``updated_at``);
* on PostgreSQL, the same fail-closed ``org_isolation`` RLS policy keyed on the
  ``app.current_org_id`` GUC — a run's trace is recon-sensitive and must never
  cross tenants. The whole RLS block is a clean no-op on sqlite (the unit-test DB).

Revision ID: 0012_run_events
Revises: 0011_finding_closure
Create Date: 2026-07-09
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0012_run_events"
down_revision = "0011_finding_closure"
branch_labels = None
depends_on = None

_JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

# Same fail-closed predicate the other tenant tables use (see 0002_org_rls):
# unset/cleared GUC → NULL → predicate never true → zero rows (fail-closed).
_ORG_PREDICATE = "org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid"
_POLICY = "org_isolation"


def upgrade() -> None:
    op.create_table(
        "run_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        # Plain indexed UUID, NO FK (mirrors audit_events): the trace stands alone.
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("data", _JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_run_events"),
    )
    op.create_index("ix_run_events_run_id", "run_events", ["run_id"], unique=False)
    op.create_index("ix_run_events_org_id", "run_events", ["org_id"], unique=False)
    # The exact SSE tail query: WHERE run_id = ? AND seq > ? ORDER BY seq.
    op.create_index(
        "ix_run_events_run_id_seq", "run_events", ["run_id", "seq"], unique=False
    )

    if op.get_bind().dialect.name != "postgresql":
        return  # RLS is a Postgres feature; no-op on sqlite (unit-test DB).
    op.execute("ALTER TABLE run_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE run_events FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY {_POLICY} ON run_events "
        f"USING ({_ORG_PREDICATE}) "
        f"WITH CHECK ({_ORG_PREDICATE})"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"DROP POLICY IF EXISTS {_POLICY} ON run_events")
        op.execute("ALTER TABLE run_events NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE run_events DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_run_events_run_id_seq", table_name="run_events")
    op.drop_index("ix_run_events_org_id", table_name="run_events")
    op.drop_index("ix_run_events_run_id", table_name="run_events")
    op.drop_table("run_events")
