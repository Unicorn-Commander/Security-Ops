"""Authorized-target registry service (spec §4/§6).

Owns listing and registration of :class:`~app.models.target.AuthorizedTarget`
rows — the registry the authorization gate consults. A newly registered target is
always ``UNATTESTED``; it becomes scannable only after
``app.authz.attestation.attest_target`` (behind ``POST /targets/{id}/attest``,
which the route calls directly). Services own their transactions (they commit) and
emit the append-only audit rows.

Dependency direction (no cycles): services -> {audit.writer, core.errors,
repositories, models}. Nothing there imports services.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.writer import record_event
from app.core.errors import ConflictError
from app.models.audit import AuditAction
from app.models.target import AttestationStatus, AuthorizedTarget
from app.repositories.targets import TargetRepository

if TYPE_CHECKING:  # typing only — no runtime coupling / cycle
    from app.auth.sso import AuthUser
    from app.models.organization import Organization
    from app.schemas.target import TargetCreate

logger = logging.getLogger("secops.services.targets")


async def list_targets(
    session: AsyncSession,
    *,
    org: "Organization",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AuthorizedTarget], int]:
    """Return ``(items, total)`` for the calling org's registered targets.

    Org-scoped in the repository query, so tenant isolation holds without a
    separate per-row check.
    """
    return await TargetRepository(session).list(org.id, limit=limit, offset=offset)


async def register_target(
    session: AsyncSession,
    *,
    org: "Organization",
    actor: "AuthUser",
    data: "TargetCreate",
) -> AuthorizedTarget:
    """Register a new (UNATTESTED) target for the org, audited ``TARGET_REGISTERED``.

    The target is inert until attested — registration alone never authorizes a
    scan. A duplicate ``(org, kind, value)`` (the model's unique constraint) is
    surfaced as a 409 ``ConflictError`` rather than an opaque 500.
    """
    target = AuthorizedTarget(
        org_id=org.id,
        kind=data.kind,
        value=data.value,
        label=data.label,
        owner_principal=data.owner_principal,
        attestation_status=AttestationStatus.UNATTESTED,
    )
    session.add(target)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise ConflictError(
            "a target with this kind and value is already registered for this "
            "organization",
            detail={"kind": data.kind.value, "value": data.value},
        ) from exc

    await record_event(
        session,
        action=AuditAction.TARGET_REGISTERED,
        actor=actor,
        org_id=org.id,
        target=target.value,
        target_id=target.id,
        reason=f"target registered ({data.kind.value})",
        detail={"kind": data.kind.value, "value": data.value, "label": data.label},
    )
    await session.commit()
    return target


__all__ = ["list_targets", "register_target"]
