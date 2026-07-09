"""Identity route — who the caller is, for the console's account menu / settings.

``GET /me`` returns the resolved SSO principal (email, display name, coarse role,
entitlement SKUs) and the tenant it maps to (org slug + display name). It requires
SSO + the ``security-ops`` entitlement (enforced transitively via ``CurrentOrg``),
so the console can render the signed-in account, the active organization, and a
sign-out affordance without re-deriving identity client-side (the browser only
sees an opaque session cookie — the ID token is forwarded server-side).
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import CurrentOrg, EntitledUser
from app.auth.sso import UserRole
from app.core.config import settings

router = APIRouter(tags=["me"])


def _display_name(user) -> str | None:
    attrs = user.attrs or {}
    return (
        attrs.get("name")
        or attrs.get("preferred_username")
        or (user.email.split("@")[0] if user.email else None)
    )


@router.get("/me")
async def me_route(org: CurrentOrg, user: EntitledUser) -> dict:
    """Return the authenticated principal + its active organization.

    ``capabilities`` reflects the admin-only attestation methods this principal may
    actually use on this deployment (role AND install-switch), so the console can
    show/hide the break-glass / self-attest options instead of offering a method
    that would only 403. It is a UX hint, not the enforcement boundary — the gate
    still re-checks role + switch server-side on every attest.
    """
    role = getattr(user.role, "value", str(user.role))
    is_admin = user.role == UserRole.ADMIN
    return {
        "id": user.id,
        "email": user.email,
        "name": _display_name(user),
        "role": role,
        "apps": list(user.apps),
        "org": {"slug": org.slug, "name": org.name},
        "auth_source": user.auth_source,
        "capabilities": {
            "self_attest": is_admin and settings.attestation_allow_self_attest,
            "break_glass": is_admin and settings.attestation_allow_break_glass,
            # Cloud-account possession proof is NOT admin-only (the role assumption IS
            # the authorization), so this is gated on the install switch alone.
            "cloud_role": settings.attestation_allow_cloud_role,
        },
    }
