"""Uniform application errors + the FastAPI exception-handler installer.

Every business error in Security-Ops is an :class:`AppError` (or a subclass). An
error carries a machine-readable ``code``, a human ``message``, an HTTP
``status_code``, and an optional structured ``detail``.
:func:`install_exception_handlers` wires FastAPI so that *all* errors — our
:class:`AppError`\\ s, request-validation failures, bare ``HTTPException``\\ s, and
anything unexpected — serialize to the single envelope the SPA already speaks::

    {"error": {"code": "...", "message": "...", "detail": ... | null}}

(See ``frontend/src/pages/*.jsx`` and :mod:`app.main`.) Keeping that shape
uniform is exactly why the handlers below fold the framework's own exceptions
into it too.

Import hygiene: this module imports only FastAPI/Starlette + stdlib — never an
app-internal module — so it can never introduce an import cycle and stays safe to
import from anywhere (auth, api, engine).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("secops.errors")

__all__ = [
    "AppError",
    "NotFoundError",
    "ForbiddenError",
    "ConflictError",
    "ValidationAppError",
    "install_exception_handlers",
]


def error_envelope(
    code: str, message: str, detail: Any | None = None
) -> dict[str, Any]:
    """Build the canonical error body the SPA parses: ``{"error": {...}}``."""
    return {"error": {"code": code, "message": message, "detail": detail}}


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


class AppError(Exception):
    """Base application error → a uniform HTTP error response.

    Subclasses pin ``status_code`` + ``code`` as class attributes; any field can
    still be overridden per-instance via keyword. The constructor matches every
    call site in the app, e.g.::

        AppError(msg, code="unauthorized", status_code=401)
        ForbiddenError("admin role required", detail={"role": role})
        raise NotFoundError("Engagement not found")

    Subclasses that need a distinct code (e.g. ``EntitlementDenied``) may set
    ``self.code`` after ``super().__init__(...)`` — instance attributes win over
    the class defaults.
    """

    #: Defaults. Subclasses override the class attributes; callers override
    #: per-instance through the constructor keywords.
    status_code: int = 500
    code: str = "internal_error"
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        detail: Any | None = None,
    ) -> None:
        if message is not None:
            self.message = message
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code
        self.detail = detail
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """The inner error object: ``{"code", "message", "detail"}``."""
        return {"code": self.code, "message": self.message, "detail": self.detail}

    def envelope(self) -> dict[str, Any]:
        """The full response body the SPA parses: ``{"error": {...}}``."""
        return {"error": self.to_dict()}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"{type(self).__name__}(message={self.message!r}, code={self.code!r}, "
            f"status_code={self.status_code}, detail={self.detail!r})"
        )


class NotFoundError(AppError):
    """The requested resource does not exist or is not visible to the caller (404)."""

    status_code = 404
    code = "not_found"
    message = "Resource not found."


class ForbiddenError(AppError):
    """Authenticated but not permitted to perform the action (403).

    Base of the operator-authz denials (SSO role / entitlement gate).
    """

    status_code = 403
    code = "forbidden"
    message = "Forbidden."


class ConflictError(AppError):
    """The request conflicts with current state — duplicate or illegal transition (409)."""

    status_code = 409
    code = "conflict"
    message = "Conflict with current resource state."


class ValidationAppError(AppError):
    """Semantic / business-rule validation failed (422).

    Distinct from FastAPI's request-*schema* validation (which also renders 422
    through :func:`install_exception_handlers`): this is raised by services when a
    well-formed request cannot be processed (e.g. a run with no targets).
    """

    status_code = 422
    code = "validation_error"
    message = "Validation failed."


# ---------------------------------------------------------------------------
# HTTP status → machine-code slugs (for normalizing framework HTTPExceptions)
# ---------------------------------------------------------------------------

_HTTP_CODE_SLUGS: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    406: "not_acceptable",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    501: "not_implemented",
    502: "bad_gateway",
    503: "service_unavailable",
    504: "gateway_timeout",
}


def _http_code_slug(status_code: int) -> str:
    return _HTTP_CODE_SLUGS.get(status_code, f"http_{status_code}")


# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------


def install_exception_handlers(app: FastAPI) -> None:
    """Register the handlers that render every error as the uniform envelope.

    One handler on the :class:`AppError` base is sufficient for the whole
    hierarchy: Starlette resolves handlers by walking ``type(exc).__mro__``
    most-specific-first, and each subclass carries its own ``status_code`` — so
    every ``AppError`` subclass (incl. ``NotFoundError`` → 404,
    ``ForbiddenError`` → 403, ``ConflictError`` → 409, ``ValidationAppError`` →
    422, and app-defined ones like ``EntitlementDenied``/``HandoffError``) maps to
    the right HTTP status through it. The remaining handlers fold FastAPI's own
    request-validation errors, bare ``HTTPException``\\ s, and unexpected
    exceptions into the same ``{"error": {...}}`` shape.

    Called once from the composition root (:mod:`app.main`); idempotent enough to
    re-run in tests (later registrations replace earlier ones).
    """

    @app.exception_handler(AppError)
    async def _handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        # 5xx are our bugs → log loudly; 4xx are client/authz outcomes → info.
        log = logger.error if exc.status_code >= 500 else logger.info
        log(
            "app_error status=%s code=%s at %s %s: %s",
            exc.status_code,
            exc.code,
            request.method,
            request.url.path,
            exc.message,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=jsonable_encoder(exc.envelope()),
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_request_validation(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # jsonable_encoder is required: exc.errors() can carry non-JSON-native
        # values (e.g. ValueError ctx) that plain json.dumps would choke on.
        return JSONResponse(
            status_code=422,
            content=jsonable_encoder(
                error_envelope(
                    "validation_error",
                    "Request validation failed",
                    exc.errors(),
                )
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        code = _http_code_slug(exc.status_code)
        detail = exc.detail
        if isinstance(detail, str):
            message: str = detail
            structured: Any | None = None
        else:
            # Non-string detail (dict/list) → keep it structured; synthesize a message.
            message = code.replace("_", " ").title()
            structured = detail
        headers = getattr(exc, "headers", None) or None
        return JSONResponse(
            status_code=exc.status_code,
            content=jsonable_encoder(error_envelope(code, message, structured)),
            headers=headers,
        )

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Never leak internals to the client; full traceback goes to the log only.
        logger.exception(
            "unhandled_error at %s %s", request.method, request.url.path
        )
        return JSONResponse(
            status_code=500,
            content=error_envelope("internal_error", "Internal server error"),
        )
