"""Entitlement (SKU) gate — the ``security-ops`` product entitlement.

This is the second half of the OPERATOR authorization story (the first being SSO
in :mod:`app.auth.sso`): a validated principal must additionally carry the
``security-ops`` entitlement to use any business route. It mirrors the suite
pattern used by ``center-deep-research`` (spec §3): entitlement slugs ride on the
Keycloak principal as ``app-<slug>`` realm roles -> :attr:`AuthUser.apps`.

The blueprint aliases this module onto ``app.auth.entitlements`` so consumers
(e.g. ``app.api.deps``) can ``from app.auth.entitlements import require_entitlement``.
"""

from __future__ import annotations

import logging
from typing import Awaitable, Callable

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.sso import AuthUser, UserRole, get_current_user
from app.core.config import settings
from app.core.errors import ForbiddenError
from app.db.session import get_session

logger = logging.getLogger("secops.auth.entitlement")

# Canonical product SKU. Kept in lock-step with configuration; defaults to
# ``security-ops``.
SECURITY_OPS_SKU: str = settings.entitlement_sku


class EntitlementDenied(ForbiddenError):
    """Raised when a principal lacks the required product entitlement (HTTP 403).

    Subclasses :class:`ForbiddenError` (so it surfaces as 403 through the uniform
    error envelope) but carries the distinct ``entitlement_denied`` code.
    """

    def __init__(
        self,
        message: str = "entitlement required",
        *,
        detail: dict | None = None,
    ) -> None:
        super().__init__(message, detail=detail)
        # Distinct machine code for this specific denial (see error convention).
        self.code = "entitlement_denied"


def has_entitlement(user: AuthUser, sku: str = SECURITY_OPS_SKU) -> bool:
    """Whether ``user`` is entitled to ``sku``.

    True when the principal is an ADMIN (admins bypass entitlement) or the SKU is
    present in ``user.apps``.
    """
    if user is None:
        return False
    if user.role == UserRole.ADMIN:
        return True
    return user.has_app(sku)


async def _record_entitlement_denied(
    session: AsyncSession, user: AuthUser, sku: str
) -> None:
    """Best-effort append of an ``ENTITLEMENT_DENIED`` audit event.

    Committed explicitly: the request is about to fail with 403 and
    ``get_session`` rolls back on exception, so without a commit the evidence
    row would be discarded. Audit failure must never mask the security denial,
    hence the broad guard.
    """
    try:
        # Imported lazily to avoid any import-time coupling/cycle with the audit
        # subsystem (audit may reference AuthUser for typing).
        from app.audit.writer import record_event
        from app.models.audit import AuditAction

        await record_event(
            session,
            action=AuditAction.ENTITLEMENT_DENIED,
            actor=user,
            decision="deny",
            reason=f"missing entitlement: {sku}",
            detail={"required_sku": sku, "user_apps": list(user.apps)},
        )
        await session.commit()
    except Exception:  # pragma: no cover - defensive; never mask the denial
        logger.warning(
            "failed to record ENTITLEMENT_DENIED audit event for actor=%s sku=%s",
            getattr(user, "id", "?"),
            sku,
            exc_info=True,
        )
        try:
            await session.rollback()
        except Exception:
            pass


def require_entitlement(
    sku: str = SECURITY_OPS_SKU,
) -> Callable[..., Awaitable[AuthUser]]:
    """FastAPI dependency FACTORY gating a route on the given entitlement SKU.

    The returned dependency depends on :func:`get_current_user` (SSO) and the DB
    session; on denial it records an ``ENTITLEMENT_DENIED`` audit event, then
    raises :class:`EntitlementDenied` (HTTP 403). Usage::

        EntitledUser = Annotated[AuthUser, Depends(require_entitlement())]
    """

    async def _require_entitlement(
        user: AuthUser = Depends(get_current_user),
        session: AsyncSession = Depends(get_session),
    ) -> AuthUser:
        if has_entitlement(user, sku):
            return user
        await _record_entitlement_denied(session, user, sku)
        raise EntitlementDenied(
            f"entitlement required: {sku}",
            detail={"required_sku": sku, "user_apps": list(user.apps)},
        )

    return _require_entitlement


__all__ = [
    "SECURITY_OPS_SKU",
    "EntitlementDenied",
    "has_entitlement",
    "require_entitlement",
]
