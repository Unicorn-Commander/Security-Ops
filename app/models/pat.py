"""PersonalAccessToken — durable agent credentials for the MCP surface (agent parity).

An agent drives Security-Ops through the MCP server with the *same* authority a
human operator has in the console. To do that without a browser SSO flow it
presents a long-lived **Personal Access Token** (prefix ``secops_pat_``) instead
of a short-lived Keycloak JWT. This table is that credential registry.

Only a SHA-256 **hash** of the token is ever stored (:mod:`app.security.pat`
generates the secret, returns it exactly once, and persists the digest) — the
plaintext is unrecoverable from the database, so a table leak never yields a
usable key. Each row also captures the minting operator's tenant binding
(``org_slug``) and granted entitlement SKUs (``scopes`` → :attr:`AuthUser.apps`)
so a PAT resolves to the same principal — org scope + entitlement + RLS — the
HTTP deps would build for that operator.

Deliberately NOT org-scoped by Postgres RLS: like ``organizations``, a PAT is
looked up by digest *before* the request's org context (the ``app.current_org_id``
GUC) is known — it is the thing that *establishes* that context. Migration
``0003_personal_access_tokens`` therefore adds it with no ``org_isolation``
policy (mirroring the bootstrapping carve-out documented in ``0002_org_rls``).
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin

# JSONB on Postgres, portable JSON elsewhere (tests run on aiosqlite).
_JSONB = JSON().with_variant(JSONB(), "postgresql")


class PersonalAccessToken(UUIDMixin, TimestampMixin, Base):
    """A hashed, durable API key an agent presents to the MCP server.

    The secret itself lives nowhere in this row: ``token_hash`` is the SHA-256
    hex digest the lookup path matches against, and ``token_prefix`` is a short,
    non-secret fragment (``secops_pat_ab12cd…``) the console can display so a
    human can tell their keys apart without ever seeing the secret again.
    """

    __tablename__ = "personal_access_tokens"

    # The operator this key acts as (the SSO principal id) + their email for
    # display / audit. A PAT never elevates beyond the minting operator.
    owner_user_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    owner_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Tenant binding captured at mint time — the PAT acts within exactly this org
    # (resolved to an Organization by slug at auth time, same as a JWT principal).
    org_slug: Mapped[str] = mapped_column(Text, nullable=False, index=True)

    # Human label for the key ("ci-scanner", "claude-code", …).
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # Granted entitlement SKUs → AuthUser.apps (so the entitlement gate still bites).
    scopes: Mapped[list] = mapped_column(_JSONB, nullable=False, default=list)

    # Non-secret display fragment; the full secret is returned once and never stored.
    token_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    # SHA-256 hex digest (64 chars) of the plaintext token — the lookup key.
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debug convenience
        return (
            f"<PersonalAccessToken id={self.id} owner={self.owner_user_id!r} "
            f"prefix={self.token_prefix!r} revoked={self.revoked_at is not None}>"
        )
