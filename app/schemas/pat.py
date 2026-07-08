"""Personal Access Token schemas (agent-credential minting).

``PATCreate`` is the body of ``POST /api/v1/pats``; ``PATRead`` mirrors the
non-secret columns of :class:`app.models.pat.PersonalAccessToken` 1:1 (the token
digest is NEVER surfaced). ``PATCreated`` extends the read shape with the
plaintext token — returned exactly once, at creation, and never again.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class PATCreate(BaseModel):
    """Mint a new agent key for the current operator.

    ``scopes`` defaults to empty: the mint route fills it with the operator's own
    entitlement SKUs so the key inherits (never exceeds) the minter's access.
    ``owner``/``org`` come from the SSO principal, not the body.
    """

    name: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None


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
