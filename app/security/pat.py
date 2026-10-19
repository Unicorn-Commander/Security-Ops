"""Personal Access Token service — mint, hash, and verify durable agent keys.

This is the credential layer under the MCP server (:mod:`app.mcp`). A human
operator mints a PAT in the console (``POST /api/v1/pats``); an agent then presents
it as a Bearer token on every MCP call and is resolved to the *same* org-scoped,
entitled principal the minting operator carries.

Secret handling (never log or store the plaintext):

* :func:`create_pat` generates ``secops_pat_<url-safe-secret>``, stores ONLY its
  SHA-256 digest (+ a short non-secret prefix for display), and returns the
  plaintext exactly once to the caller. The plaintext is unrecoverable afterwards.
* :func:`verify_pat` hashes a presented token and looks the row up by digest,
  rejecting revoked/expired keys, and stamps ``last_used_at`` on success.

Lifetime (mint-side only): a PAT's authority is FROZEN at mint time — the MCP auth
path rebuilds the principal from the stored row and never re-checks live
entitlement — so :func:`create_pat` ALWAYS time-boxes a new key
(``pat_default_ttl_days`` when the request omits an expiry, ``pat_max_ttl_days`` as
the hard ceiling). A never-expiring key is no longer mintable. :func:`verify_pat` is
deliberately UNCHANGED: rows already issued with a NULL expiry stay valid until they
are revoked, because there are live ones in production.

Transaction contract (suite convention): these helpers **flush, never commit** —
the caller (the mint route / the MCP auth scope) owns the transaction boundary,
exactly like the repositories and the audit writer.

Dependency direction (no cycles): security.pat -> {models.pat, core, db}. It never
imports auth / authz / api.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import ValidationAppError
from app.models.pat import PersonalAccessToken

logger = logging.getLogger("secops.security.pat")

#: The stable, human-recognizable prefix every Security-Ops PAT carries. The MCP
#: auth path keys off this to route a Bearer credential to PAT verification rather
#: than JWT validation.
TOKEN_PREFIX = "secops_pat_"

#: Bytes of entropy behind the url-safe secret body (well above brute-force reach).
_SECRET_BYTES = 32

__all__ = [
    "TOKEN_PREFIX",
    "MintedPAT",
    "bounded_expiry",
    "hash_token",
    "is_pat_token",
    "generate_token",
    "create_pat",
    "verify_pat",
    "list_pats",
    "revoke_pat",
]


@dataclass
class MintedPAT:
    """The result of minting a key: the persisted row + its one-time plaintext.

    ``plaintext`` is returned to the operator exactly once (the API surfaces it in
    the ``POST /api/v1/pats`` response and never again) — it is NOT stored on the
    row and must never be logged.
    """

    record: PersonalAccessToken
    plaintext: str


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def bounded_expiry(expires_at: datetime | None) -> datetime:
    """Return the expiry a NEW key must carry, or raise if the request is unusable.

    Mint-side lifetime policy, in one place:

    * ``None`` (omitted / explicit ``null``) => ``now + pat_default_ttl_days``. A
      never-expiring agent key is not mintable — the console's old "No expiry"
      choice resolves to the default lifetime instead of a permanent credential.
    * a supplied instant in the past (or now) => refused, as before.
    * a supplied instant beyond ``now + pat_max_ttl_days`` => refused. Without a
      ceiling ``expires_at`` = year 3000 was simply "no expiry" spelled differently.

    A supplied, in-bounds value is returned unchanged so an explicit expiry is
    persisted exactly as the caller asked for it. Naive datetimes are read as UTC
    for the comparison only. This is NOT applied on the verify path: existing rows
    (including NULL-expiry ones minted before this bound existed) are untouched.
    """
    now = _utcnow()
    if expires_at is None:
        return now + timedelta(days=settings.pat_default_ttl_days)

    requested = _aware(expires_at) or now
    if requested <= now:
        raise ValidationAppError(
            "personal access token expiry must be in the future",
            code="pat_expiry_invalid",
            detail={"field": "expires_at"},
        )
    max_days = settings.pat_max_ttl_days
    if requested > now + timedelta(days=max_days):
        raise ValidationAppError(
            f"personal access token expiry must be within {max_days} days",
            code="pat_expiry_too_long",
            detail={"field": "expires_at", "max_ttl_days": max_days},
        )
    return expires_at


def is_pat_token(token: str | None) -> bool:
    """Whether ``token`` is a Security-Ops PAT (vs. a Keycloak JWT)."""
    return bool(token) and token.startswith(TOKEN_PREFIX)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest stored/looked-up for ``token`` (never the token)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> tuple[str, str]:
    """Mint a fresh secret. Returns ``(plaintext, token_prefix)``.

    ``plaintext`` is ``secops_pat_`` + a url-safe secret; ``token_prefix`` is a
    short, non-secret leading fragment safe to persist for display.
    """
    plaintext = f"{TOKEN_PREFIX}{secrets.token_urlsafe(_SECRET_BYTES)}"
    return plaintext, plaintext[: len(TOKEN_PREFIX) + 6]


async def create_pat(
    session: AsyncSession,
    owner_user_id: str,
    name: str,
    scopes: list[str],
    expires_at: datetime | None = None,
    *,
    org_slug: str,
    owner_email: str | None = None,
    allowed_scopes: Collection[str],
) -> MintedPAT:
    """Create a Personal Access Token, returning its plaintext exactly once.

    Persists only the token's SHA-256 digest (+ a display prefix); the plaintext is
    on the returned :class:`MintedPAT` and nowhere else. ``org_slug`` binds the key
    to the minting operator's tenant and ``scopes`` are the entitlement SKUs the
    resolved principal will carry (so the entitlement gate still applies to the
    agent). The key is ALWAYS time-boxed: ``expires_at`` must be in the future and
    within ``pat_max_ttl_days``; omitting it yields ``pat_default_ttl_days`` rather
    than a permanent credential (see :func:`bounded_expiry`). Flushes; the caller
    owns the commit.

    ``org_slug`` / ``owner_email`` are keyword-only additions to the documented
    ``create_pat(session, owner_user_id, name, scopes, expires_at=None)`` signature
    (the tenant binding a durable, browserless credential needs). ``allowed_scopes``
    is the minting caller's entitlement ceiling and is required so every caller
    enforces the same bound.
    """
    clean_name = (name or "").strip()
    if not clean_name:
        raise ValidationAppError(
            "a personal access token requires a name",
            code="pat_name_required",
            detail={"field": "name"},
        )
    requested_scopes = list(scopes or [])
    excess = sorted(set(requested_scopes) - set(allowed_scopes))
    if excess:
        raise ValidationAppError(
            "personal access token scopes cannot exceed the caller's entitlements",
            code="pat_scopes_exceed_caller",
            detail={"field": "scopes", "not_entitled": excess},
        )
    # Always time-boxed: refuses a past/over-long expiry, defaults an omitted one.
    expires_at = bounded_expiry(expires_at)

    plaintext, prefix = generate_token()
    record = PersonalAccessToken(
        id=uuid.uuid4(),
        owner_user_id=str(owner_user_id),
        owner_email=owner_email,
        org_slug=org_slug,
        name=clean_name,
        scopes=requested_scopes,
        token_prefix=prefix,
        token_hash=hash_token(plaintext),
        expires_at=expires_at,
    )
    session.add(record)
    await session.flush()
    # Never log the plaintext — only the non-secret id/prefix.
    logger.info(
        "pat.created id=%s owner=%s prefix=%s org=%s",
        record.id,
        record.owner_user_id,
        record.token_prefix,
        org_slug,
    )
    return MintedPAT(record=record, plaintext=plaintext)


async def verify_pat(session: AsyncSession, token: str) -> PersonalAccessToken | None:
    """Resolve a presented PAT to its row, or ``None`` if it is not usable.

    Returns ``None`` (never raises) when the token is not a PAT, is unknown, is
    revoked, or has expired — the MCP auth layer maps a ``None`` to an auth
    refusal. On success it stamps ``last_used_at`` (flush, no commit).
    """
    if not is_pat_token(token):
        return None
    digest = hash_token(token)
    record = (
        await session.execute(
            select(PersonalAccessToken).where(PersonalAccessToken.token_hash == digest)
        )
    ).scalar_one_or_none()
    if record is None:
        return None

    now = _utcnow()
    if record.revoked_at is not None:
        return None
    expires_at = _aware(record.expires_at)
    if expires_at is not None and expires_at <= now:
        return None

    record.last_used_at = now
    await session.flush()
    return record


async def list_pats(
    session: AsyncSession, *, owner_user_id: str, org_slug: str
) -> list[PersonalAccessToken]:
    """Return the caller's non-secret PAT rows for their org, newest first."""
    stmt = (
        select(PersonalAccessToken)
        .where(
            PersonalAccessToken.owner_user_id == str(owner_user_id),
            PersonalAccessToken.org_slug == org_slug,
        )
        .order_by(PersonalAccessToken.created_at.desc(), PersonalAccessToken.id.desc())
    )
    return list((await session.execute(stmt)).scalars().all())


async def revoke_pat(
    session: AsyncSession,
    pat_id: uuid.UUID,
    *,
    owner_user_id: str,
    org_slug: str,
) -> PersonalAccessToken | None:
    """Revoke one of the caller's PATs (idempotent). Returns the row, or ``None``.

    Scoped to ``owner_user_id`` + ``org_slug`` so an operator can only revoke their
    own tenant's keys. Sets ``revoked_at`` (flush; the route owns the commit); a
    key already revoked keeps its original revocation timestamp.
    """
    record = (
        await session.execute(
            select(PersonalAccessToken).where(
                PersonalAccessToken.id == pat_id,
                PersonalAccessToken.owner_user_id == str(owner_user_id),
                PersonalAccessToken.org_slug == org_slug,
            )
        )
    ).scalar_one_or_none()
    if record is None:
        return None
    if record.revoked_at is None:
        record.revoked_at = _utcnow()
        await session.flush()
        logger.info("pat.revoked id=%s owner=%s", record.id, record.owner_user_id)
    return record
