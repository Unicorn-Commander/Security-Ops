"""Personal Access Token schemas (agent-credential minting).

``PATCreate`` is the body of ``POST /api/v1/pats``; ``PATRead`` mirrors the
non-secret columns of :class:`app.models.pat.PersonalAccessToken` 1:1 (the token
digest is NEVER surfaced). ``PATCreated`` extends the read shape with the
plaintext token — returned exactly once, at creation, and never again.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.time import normalize_datetime_to_utc


class PATCreate(BaseModel):
    """Mint a new agent key for the current operator.

    ``scopes`` defaults to empty: the mint route fills it with the operator's own
    entitlement SKUs so the key inherits (never exceeds) the minter's access. A
    non-empty list may only NARROW that set — anything the caller is not entitled to
    is refused (``pat_scopes_exceed_caller``). ``owner``/``org`` come from the SSO
    principal, not the body.

    ``expires_at`` is optional but no longer unbounded (BREAKING vs. the original
    shape, where ``null`` meant "never"): omitting it mints a key that lapses in
    ``pat_default_ttl_days``, and any instant past ``pat_max_ttl_days`` is refused
    (``pat_expiry_too_long``). A PAT's authority is frozen at mint time, so it has to
    lapse on its own. Existing NULL-expiry keys still verify — the bound is mint-side.
    """

    name: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(default_factory=list)
    expires_at: datetime | None = Field(
        default=None,
        description=(
            "When the key stops working. Omit for the default lifetime; "
            "'never' is not mintable and an over-long expiry is refused."
        ),
    )

    @field_validator("expires_at", mode="before")
    @classmethod
    def _normalize_expiry(cls, value: object) -> object:
        """Apply the client request convention before mint-side bounds checks."""
        return normalize_datetime_to_utc(value)


class PATRead(BaseModel):
    """A PAT's non-secret metadata (safe to list). Carries no token material."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    owner_user_id: str
    owner_email: str | None = None
    org_slug: str
    scopes: list[str] = Field(default_factory=list)
    token_prefix: str
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class PATCreated(PATRead):
    """The one-time creation response — includes the plaintext ``token``.

    This is the ONLY time the secret is ever returned; it is not stored and cannot
    be recovered. Clients must capture it here.
    """

    token: str
