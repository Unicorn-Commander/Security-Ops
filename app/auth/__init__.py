"""``app.auth`` — operator authorization: SSO (Keycloak) + entitlement (SKU).

Physical layout of this module ("auth-mw"):

  * :mod:`app.auth.sso`         — Keycloak OIDC token validation, roles, and the
                                  current-user FastAPI dependencies.
  * :mod:`app.auth.entitlement` — the ``security-ops`` product entitlement gate.

The shared blueprint's canonical import surface splits these symbols across
``app.auth.keycloak``, ``app.auth.roles``, ``app.auth.middleware`` and
``app.auth.entitlements``. Rather than duplicate code into four files, those
canonical dotted paths are registered as aliases onto the two physical modules
below, so **every** consumer import resolves identically:

    from app.auth.keycloak import validate_token, keycloak_enabled, KeycloakValidationError
    from app.auth.roles import UserRole, map_keycloak_roles
    from app.auth.middleware import AuthUser, get_current_user, get_current_user_optional, require_admin
    from app.auth.entitlements import SECURITY_OPS_SKU, require_entitlement, has_entitlement, EntitlementDenied

...as well as the physical/short forms (``from app.auth.sso import ...`` and
``from app.auth import ...``).
"""

from __future__ import annotations

import sys

from app.auth import entitlement as entitlement
from app.auth import sso as sso

# --- Public surface: ``from app.auth import X`` -----------------------------
from app.auth.sso import (
    AuthUser,
    KeycloakValidationError,
    UserRole,
    bearer_scheme,
    get_current_user,
    get_current_user_optional,
    keycloak_enabled,
    map_keycloak_roles,
    principal_from_claims,
    require_admin,
    validate_token,
)
from app.auth.entitlement import (
    EntitlementDenied,
    SECURITY_OPS_SKU,
    has_entitlement,
    require_entitlement,
)

# --- Canonical blueprint module aliases -------------------------------------
# keycloak / roles / middleware all live physically in ``app.auth.sso``;
# entitlements lives in ``app.auth.entitlement``. ``setdefault`` avoids
# clobbering should a real submodule ever be added, and is import-order safe:
# a package's ``__init__`` runs before any submodule of it is resolved, so these
# aliases are in ``sys.modules`` by the time ``from app.auth.middleware import ...``
# is evaluated.
sys.modules.setdefault(f"{__name__}.keycloak", sso)
sys.modules.setdefault(f"{__name__}.roles", sso)
sys.modules.setdefault(f"{__name__}.middleware", sso)
sys.modules.setdefault(f"{__name__}.entitlements", entitlement)

__all__ = [
    # keycloak
    "KeycloakValidationError",
    "keycloak_enabled",
    "validate_token",
    # roles
    "UserRole",
    "map_keycloak_roles",
    # middleware
    "AuthUser",
    "bearer_scheme",
    "principal_from_claims",
    "get_current_user",
    "get_current_user_optional",
    "require_admin",
    # entitlements
    "SECURITY_OPS_SKU",
    "EntitlementDenied",
    "has_entitlement",
    "require_entitlement",
]
