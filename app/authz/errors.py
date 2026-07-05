"""app.authz.errors — the TARGET-authorization 403 hierarchy (spec §4).

These are the exceptions the gate raises when a target is refused. They are the
*target* authorization denials (what a scan may touch) and are deliberately a
distinct hierarchy from the *operator* authorization denial
(:class:`app.core.errors.ForbiddenError`, "who may drive the app") — the codebase
keeps those two concerns apart on purpose, so they can be caught independently.

Every one is an :class:`app.core.errors.AppError` subclass, which means the
suite's single exception handler (``install_exception_handlers``) renders it as
the uniform envelope ``{"error": {"code", "message", "detail"}}`` at the pinned
HTTP status — here always **403**. Each subclass pins a distinct ``code`` (as a
class attribute, matching the suite convention for ``NotFoundError`` /
``ForbiddenError`` / …); those codes are exactly the keys of
``app.authz.gate._ERROR_BY_CODE``, so a :class:`ScopeDecision` code maps 1:1 to
the class raised.

The gate raises them as ``SomeDenial(decision.reason)`` — the positional message
overrides the class default per-instance (see ``AppError.__init__``), while the
class ``code`` / ``status_code`` are inherited. No custom ``__init__`` is needed.

Dependency direction (no cycles): authz.errors -> core.errors only.
"""

from __future__ import annotations

from app.core.errors import AppError

__all__ = [
    "AuthorizationDenied",
    "EngagementInactive",
    "EngagementExpired",
    "OutsideTimeWindow",
    "EmergencyStopEngaged",
    "ScopeViolation",
    "TargetExcluded",
    "TargetNotAttested",
    "AttestationExpired",
]


class AuthorizationDenied(AppError):
    """Base of every target-authorization denial — always HTTP 403.

    Also the fallback the gate raises for an unrecognized decision code
    (``_ERROR_BY_CODE.get(code, AuthorizationDenied)``), so it is concrete and
    directly instantiable, not abstract.
    """

    status_code = 403
    code = "authorization_denied"
    message = "The scope-of-engagement gate denied this target."


class EngagementInactive(AuthorizationDenied):
    """The engagement does not exist or is not in the ``ACTIVE`` state."""

    code = "engagement_inactive"
    message = "Engagement is not active."


class EngagementExpired(AuthorizationDenied):
    """The engagement's ``expires_at`` has passed."""

    code = "engagement_expired"
    message = "Engagement has expired."


class OutsideTimeWindow(AuthorizationDenied):
    """The current time is outside the engagement's rules-of-engagement window."""

    code = "outside_time_window"
    message = "Current time is outside the engagement time window."


class EmergencyStopEngaged(AuthorizationDenied):
    """A kill-switch is engaged — the engagement's or the global one."""

    code = "emergency_stop_engaged"
    message = "An emergency stop is engaged."


class ScopeViolation(AuthorizationDenied):
    """The target is not within the engagement's in-scope rules."""

    code = "scope_violation"
    message = "Target is not within the engagement's in-scope rules."


class TargetExcluded(AuthorizationDenied):
    """The target matches an explicit scope exclusion (exclusion wins)."""

    code = "target_excluded"
    message = "Target matches an explicit scope exclusion."


class TargetNotAttested(AuthorizationDenied):
    """No registered, valid-attested :class:`AuthorizedTarget` covers the target."""

    code = "target_not_attested"
    message = "No valid attested target covers this target."


class AttestationExpired(AuthorizationDenied):
    """A covering target exists but its attestation is expired or revoked."""

    code = "attestation_expired"
    message = "The covering target's attestation is expired or revoked."
