"""personal access tokens — durable agent credentials for the MCP surface

Adds the ``personal_access_tokens`` table (see :mod:`app.models.pat`): the
registry of hashed, long-lived API keys an agent presents to the MCP server so it
drives Security-Ops with the same authority a human operator has in the console.

Only the SHA-256 digest of a token is stored (``token_hash``, UNIQUE) — never the
plaintext. Each row also captures its minting operator's tenant binding
(``org_slug``) and granted entitlement SKUs (``scopes``) so a PAT resolves to the
same org-scoped, entitled principal a JWT would.

RLS: this table deliberately gets NO ``org_isolation`` policy. Like
``organizations`` (see ``0002_org_rls``), a PAT is looked up by digest BEFORE the
request's ``app.current_org_id`` GUC is known — it is what *establishes* the org
context — so a tenant-scoped policy would make it unlookupable. Column/constraint
names follow the ``app.db.base`` naming_convention for clean autogenerate diffs.

Revision ID: 0003_personal_access_tokens
Revises: 0002_org_rls
Create Date: 2026-07-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0003_personal_access_tokens"
down_revision = "0002_org_rls"
branch_labels = None
depends_on = None

# JSONB on Postgres; the generic JSON variant everywhere else (parity with the models).
_JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "personal_access_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_user_id", sa.Text(), nullable=False),
        sa.Column("owner_email", sa.Text(), nullable=True),
        sa.Column("org_slug", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("scopes", _JSONB, nullable=False),
        sa.Column("token_prefix", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_personal_access_tokens"),
        sa.UniqueConstraint("token_hash", name="uq_personal_access_tokens_token_hash"),
    )
    op.create_index(
        "ix_personal_access_tokens_owner_user_id",
        "personal_access_tokens",
        ["owner_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_personal_access_tokens_org_slug",
        "personal_access_tokens",
        ["org_slug"],
        unique=False,
    )
    op.create_index(
        "ix_personal_access_tokens_token_hash",
        "personal_access_tokens",
        ["token_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_personal_access_tokens_token_hash", table_name="personal_access_tokens")
    op.drop_index("ix_personal_access_tokens_org_slug", table_name="personal_access_tokens")
    op.drop_index("ix_personal_access_tokens_owner_user_id", table_name="personal_access_tokens")
    op.drop_table("personal_access_tokens")
