"""Personal Access Token tests — mint, hash-only storage, verify accept/reject.

Exercised against a real in-memory session (no HTTP), per the suite convention.
The load-bearing guarantees under test:

* :func:`app.security.pat.create_pat` returns the plaintext ONCE and stores only a
  SHA-256 digest (the plaintext never lands in the row);
* :func:`app.security.pat.verify_pat` accepts a good token and rejects an unknown,
  revoked, or expired one;
* the mint route (``POST /api/v1/pats``) surfaces the token once and defaults the
  key's scopes to the operator's entitlements.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.auth.sso import AuthUser, UserRole
from app.security.pat import (
    TOKEN_PREFIX,
    create_pat,
    hash_token,
    revoke_pat,
    verify_pat,
)
from tests.conftest import make_org, utcnow


def _agent_user(org_slug: str = "pilot") -> AuthUser:
    return AuthUser(
        id="agent-1",
        email="demo@example.invalid",
        role=UserRole.OPERATOR,
        org_slug=org_slug,
        apps=["security-ops"],
    )


async def test_create_pat_returns_plaintext_once_and_stores_only_hash(db_session):
    org = await make_org(db_session, slug="pilot")
    minted = await create_pat(
        db_session, "agent-1", "ci-key", ["security-ops"], org_slug=org.slug
    )
    await db_session.commit()

    # Plaintext is the well-known prefix + secret, and never equals the stored value.
    assert minted.plaintext.startswith(TOKEN_PREFIX)
    assert minted.record.token_hash == hash_token(minted.plaintext)
    assert minted.plaintext not in (minted.record.token_hash, minted.record.token_prefix)
    # Only a short, non-secret prefix is retained for display.
    assert minted.record.token_prefix.startswith(TOKEN_PREFIX)
    assert len(minted.record.token_prefix) < len(minted.plaintext)


async def test_verify_pat_accepts_good_token_and_stamps_last_used(db_session):
    org = await make_org(db_session, slug="pilot")
    minted = await create_pat(db_session, "agent-1", "k", ["security-ops"], org_slug=org.slug)
    await db_session.commit()

    record = await verify_pat(db_session, minted.plaintext)
    assert record is not None
    assert record.id == minted.record.id
    assert record.last_used_at is not None


async def test_verify_pat_rejects_unknown_revoked_and_expired(db_session):
    org = await make_org(db_session, slug="pilot")

    # Unknown token.
    assert await verify_pat(db_session, f"{TOKEN_PREFIX}nope") is None
    # A non-PAT credential (a JWT) is not a PAT — not our lookup.
    assert await verify_pat(db_session, "eyJ.a.b") is None

    # Revoked.
    revoked = await create_pat(db_session, "agent-1", "r", ["security-ops"], org_slug=org.slug)
    await db_session.commit()
    await revoke_pat(db_session, revoked.record.id, owner_user_id="agent-1", org_slug=org.slug)
    await db_session.commit()
    assert await verify_pat(db_session, revoked.plaintext) is None

    # Expired.
    expired = await create_pat(db_session, "agent-1", "e", ["security-ops"], org_slug=org.slug)
    expired.record.expires_at = utcnow() - timedelta(hours=1)
    await db_session.commit()
    assert await verify_pat(db_session, expired.plaintext) is None


async def test_create_pat_rejects_past_expiry(db_session):
    from app.core.errors import ValidationAppError

    org = await make_org(db_session, slug="pilot")
    with pytest.raises(ValidationAppError):
        await create_pat(
            db_session,
            "agent-1",
            "bad",
            ["security-ops"],
            utcnow() - timedelta(days=1),
            org_slug=org.slug,
        )


async def test_mint_route_returns_token_once_and_defaults_scopes(db_session):
    from app.api.pats import create_pat_route
    from app.schemas.pat import PATCreate

    org = await make_org(db_session, slug="pilot")
    user = _agent_user(org.slug)

    created = await create_pat_route(
        PATCreate(name="claude-code"), db_session, org, user
    )
    # The plaintext is present exactly here.
    assert created.token.startswith(TOKEN_PREFIX)
    # Scopes defaulted to the operator's own entitlements (never broader).
    assert created.scopes == ["security-ops"]
    assert created.owner_user_id == "agent-1"

    # And the minted key actually authenticates.
    record = await verify_pat(db_session, created.token)
    assert record is not None and record.org_slug == org.slug
