"""Personal Access Token tests — mint, hash-only storage, verify accept/reject.

Exercised against a real in-memory session (no HTTP), per the suite convention.
The load-bearing guarantees under test:

* :func:`app.security.pat.create_pat` returns the plaintext ONCE and stores only a
  SHA-256 digest (the plaintext never lands in the row);
* :func:`app.security.pat.verify_pat` accepts a good token and rejects an unknown,
  revoked, or expired one;
* the mint route (``POST /api/v1/pats``) surfaces the token once and defaults the
  key's scopes to the operator's entitlements;
* minting is always TIME-BOXED (no permanent agent keys) and a body-supplied scope
  list can only narrow the caller's entitlements — while verification is unchanged,
  so keys already issued with a NULL expiry keep working.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.auth.sso import AuthUser, UserRole
from app.core.config import get_settings
from app.models.pat import PersonalAccessToken
from app.security.pat import (
    TOKEN_PREFIX,
    create_pat,
    generate_token,
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


def test_pat_create_naive_expiry_is_business_time():
    from app.schemas.pat import PATCreate

    request = PATCreate.model_validate(
        {"name": "local-expiry", "expires_at": "2026-10-16T23:30:00"}
    )

    assert request.expires_at == datetime(2026, 10, 17, 3, 30, tzinfo=UTC)


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


# ---------------------------------------------------------------------------
# Bounded lifetime (mint-side). A PAT's authority is frozen at mint time — the MCP
# auth path rebuilds the principal from the stored row and never re-checks live
# entitlement — so a key that never expires keeps the security-ops entitlement
# after the operator loses it. Minting must therefore always time-box.
# ---------------------------------------------------------------------------


async def test_create_pat_defaults_to_a_bounded_expiry_never_permanent(db_session):
    """An omitted expiry mints a key that LAPSES, not a permanent credential."""
    org = await make_org(db_session, slug="pilot")
    before = utcnow()
    minted = await create_pat(
        db_session, "agent-1", "no-expiry-please", ["security-ops"], org_slug=org.slug
    )
    await db_session.commit()

    assert minted.record.expires_at is not None, "mint must never issue a permanent key"
    ttl_days = get_settings().pat_default_ttl_days
    delta = minted.record.expires_at - before
    assert timedelta(days=ttl_days - 1) < delta <= timedelta(days=ttl_days + 1)


async def test_create_pat_rejects_expiry_beyond_max_ttl(db_session):
    """`expires_at` = far future was 'no expiry' spelled differently — refuse it."""
    from app.core.errors import ValidationAppError

    org = await make_org(db_session, slug="pilot")
    over = utcnow() + timedelta(days=get_settings().pat_max_ttl_days + 1)
    with pytest.raises(ValidationAppError) as excinfo:
        await create_pat(
            db_session, "agent-1", "forever", ["security-ops"], over, org_slug=org.slug
        )
    assert excinfo.value.code == "pat_expiry_too_long"

    # The year-3000 shape from the audit is refused by the same ceiling.
    with pytest.raises(ValidationAppError):
        await create_pat(
            db_session,
            "agent-1",
            "y3k",
            ["security-ops"],
            utcnow().replace(year=3000),
            org_slug=org.slug,
        )


async def test_create_pat_keeps_an_in_bounds_explicit_expiry_verbatim(db_session):
    """A deliberate, in-bounds lifetime is still honored exactly as asked."""
    org = await make_org(db_session, slug="pilot")
    wanted = utcnow() + timedelta(days=get_settings().pat_max_ttl_days - 1)
    minted = await create_pat(
        db_session, "agent-1", "one-year", ["security-ops"], wanted, org_slug=org.slug
    )
    await db_session.commit()
    assert minted.record.expires_at == wanted


async def test_mint_route_cannot_mint_a_permanent_key(db_session):
    """The console's old default click-path (`expires_at: null`) is time-boxed now."""
    from app.api.pats import create_pat_route
    from app.schemas.pat import PATCreate

    org = await make_org(db_session, slug="pilot")
    user = _agent_user(org.slug)

    created = await create_pat_route(
        PATCreate(name="claude-code", expires_at=None), db_session, org, user
    )
    assert created.expires_at is not None


async def test_mint_route_refuses_scopes_beyond_the_callers_entitlements(db_session):
    """A body-supplied scope list may narrow the caller's SKUs, never widen them."""
    from app.api.pats import create_pat_route
    from app.core.errors import ValidationAppError
    from app.schemas.pat import PATCreate

    org = await make_org(db_session, slug="pilot")
    user = _agent_user(org.slug)  # entitled to security-ops only

    with pytest.raises(ValidationAppError) as excinfo:
        await create_pat_route(
            PATCreate(name="greedy", scopes=["security-ops", "accounting-ops"]),
            db_session,
            org,
            user,
        )
    assert excinfo.value.code == "pat_scopes_exceed_caller"

    # Narrowing to a subset (here: exactly what the caller holds) still works.
    ok = await create_pat_route(
        PATCreate(name="narrow", scopes=["security-ops"]), db_session, org, user
    )
    assert ok.scopes == ["security-ops"]


async def test_verify_still_accepts_a_preexisting_null_expiry_key(db_session):
    """REGRESSION: keys minted before the bound existed must keep working.

    rackboy1 has live rows with ``expires_at IS NULL`` (permanent was the console's
    default click-path). The fix is mint-side ONLY: no NOT NULL constraint, no
    backfill, and verification must NOT reinterpret NULL as expired.
    """
    org = await make_org(db_session, slug="pilot")
    plaintext, prefix = generate_token()
    legacy = PersonalAccessToken(
        id=uuid.uuid4(),
        owner_user_id="agent-1",
        owner_email="demo@example.invalid",
        org_slug=org.slug,
        name="legacy-permanent-key",
        scopes=["security-ops"],
        token_prefix=prefix,
        token_hash=hash_token(plaintext),
        expires_at=None,  # exactly what production holds today
    )
    db_session.add(legacy)
    await db_session.commit()

    record = await verify_pat(db_session, plaintext)
    assert record is not None, "an existing NULL-expiry key must still authenticate"
    assert record.id == legacy.id
    assert record.expires_at is None  # not backfilled behind the operator's back
    assert record.scopes == ["security-ops"]
    assert record.last_used_at is not None


def test_console_mint_drawer_offers_no_permanent_expiry_option():
    """The console must not default (or even allow) a never-expiring token.

    'No expiry' was ``EXPIRY_OPTS[0]`` and the drawer initializes to index 0, so an
    operator who typed a name and clicked Create got a permanent key without
    touching the dropdown. Guarded here because the console has no JS test harness.
    """
    from pathlib import Path

    src = (
        Path(__file__).resolve().parent.parent
        / "frontend"
        / "src"
        / "features"
        / "settings"
        / "index.jsx"
    ).read_text(encoding="utf-8")

    opts = src.split("const EXPIRY_OPTS = [", 1)[1].split("];", 1)[0]
    assert "days: null" not in opts, "a permanent-token option is back in the console"
    assert "No expiry" not in opts
    # The default selection (index 0) is the bounded 90-day option.
    assert opts.strip().splitlines()[0].strip().startswith("{ label: '90 days'")
    # And the POST body always carries a real instant.
    assert "expires_at = new Date(Date.now() + days * 86400000).toISOString();" in src
