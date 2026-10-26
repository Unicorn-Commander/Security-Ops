"""HTTP front door for the MCP mount: 401, discovery, CORS, and the slash canonical.

FastMCP answers ``initialize`` and ``tools/list`` before any tool runs, so the
per-tool :func:`app.mcp.auth.mcp_scope` check never produces an HTTP 401.
:class:`McpHttpGuard` sits in front of that mount. Protected Resource Metadata
(RFC 9728) is registered on the parent app, outside this guard, by
:func:`install_oauth_discovery`.

The public origin is ``SECOPS_PUBLIC_BASE_URL`` when that is set, otherwise the
request's ``X-Forwarded-Proto`` and ``X-Forwarded-Host`` (else ``Host``). No
hostname is hard-coded.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings
from app.mcp.auth import McpAuthError, ensure_http_credential

logger = logging.getLogger("secops.mcp.http")

MCP_CANONICAL_PATH = "/mcp/"
PRM_PATH = "/.well-known/oauth-protected-resource"
PRM_MCP_PATH = "/.well-known/oauth-protected-resource/mcp/"
REALM = "security-ops-mcp"
RESOURCE_NAME = "Security-Ops MCP"
RESOURCE_DOCUMENTATION = "https://unicorncommander.ai/platform/bring-your-own-ai"
MCP_ALLOW_METHODS = "GET, POST, DELETE, OPTIONS"
MCP_ALLOW_HEADERS = (
    "Authorization, Content-Type, Accept, Mcp-Session-Id, "
    "Mcp-Protocol-Version, Last-Event-ID"
)
MCP_EXPOSE_HEADERS = "Mcp-Session-Id, WWW-Authenticate"
_MAX_BODY = 1024 * 1024
_HOST_BAD = set("\r\n @/?#\\")

ReceiveFn = Callable[[], Awaitable[Message]]


def _header(headers: Headers, name: str) -> str | None:
    value = headers.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _safe_host(value: str | None) -> str | None:
    if not value:
        return None
    host = value.split(",")[0].strip()
    if not host or any(char in host for char in _HOST_BAD):
        return None
    return host


def configured_public_base() -> str | None:
    """``SECOPS_PUBLIC_BASE_URL`` as ``scheme://host``, or None when unusable.

    A value with userinfo is ignored. The raw value is never logged.
    """
    raw = (settings.public_base_url or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        logger.warning("SECOPS_PUBLIC_BASE_URL ignored (http(s) origin, no userinfo)")
        return None
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def public_base_url(scope: Scope) -> str:
    """Origin the caller used to reach this process, with no path and no userinfo."""
    configured = configured_public_base()
    if configured:
        return configured
    headers = Headers(scope=scope)
    forwarded_proto = _header(headers, "x-forwarded-proto")
    proto = (forwarded_proto or "").split(",")[0].strip().lower()
    if proto not in ("http", "https"):
        proto = scope.get("scheme") if scope.get("scheme") in ("http", "https") else "http"
    host = _safe_host(_header(headers, "x-forwarded-host")) or _safe_host(_header(headers, "host"))
    if host is None:
        server = scope.get("server") or ("localhost", 80)
        hostname, port = server[0], server[1]
        host = hostname if port in (80, 443, None) else f"{hostname}:{port}"
    return f"{proto}://{host}"


def metadata_url(scope: Scope) -> str:
    return f"{public_base_url(scope)}{PRM_MCP_PATH}"


def canonical_mcp_url(scope: Scope) -> str:
    return f"{public_base_url(scope)}{MCP_CANONICAL_PATH}"


def www_authenticate(scope: Scope, *, invalid_token: bool) -> str:
    """Discovery challenge. ``error`` is set only when a bearer was presented."""
    parts = [f'Bearer realm="{REALM}"']
    if invalid_token:
        parts.append('error="invalid_token"')
    url = metadata_url(scope).replace('"', "").replace("\r", "").replace("\n", "")
    parts.append(f'resource_metadata="{url}"')
    return ", ".join(parts)


MCP_OAUTH_SCOPES = ("openid", "profile", "email", "offline_access", "mcp")


def protected_resource_document(scope: Scope) -> dict:
    """RFC 9728 document. ``authorization_servers`` is the configured issuer."""
    issuer = (settings.keycloak_issuer or "").strip().rstrip("/")
    # Exactly the scopes Keycloak's anonymous-DCR policy allows; the realm scope `mcp` carries this
    # app's audience (+ uc_uid). Anything else here (e.g. a SKU) makes client registration fail.
    scopes = list(MCP_OAUTH_SCOPES)
    return {
        "resource": canonical_mcp_url(scope),
        "authorization_servers": [issuer] if issuer else [],
        "bearer_methods_supported": ["header"],
        "scopes_supported": scopes,
        "resource_name": RESOURCE_NAME,
        "resource_documentation": RESOURCE_DOCUMENTATION,
    }


def _allowed_origins(scope: Scope) -> set[str]:
    allowed = {item for item in settings.cors_origins if item}
    allowed.update(item for item in settings.mcp_allowed_origins if item)
    allowed.add(public_base_url(scope))
    return allowed


def origin_allowed(scope: Scope, origin: str | None) -> bool:
    """A missing Origin is not a browser call. A present one must be on the list."""
    if origin is None:
        return True
    if any(char in origin for char in "\r\n"):
        return False
    return origin in _allowed_origins(scope)


def _cors_pairs(origin: str | None, *, preflight: bool) -> list[tuple[bytes, bytes]]:
    pairs: list[tuple[bytes, bytes]] = [
        (b"access-control-expose-headers", MCP_EXPOSE_HEADERS.encode("ascii")),
        (b"vary", b"Origin"),
    ]
    if origin:
        pairs.append((b"access-control-allow-origin", origin.encode("latin-1")))
    if preflight:
        pairs.extend(
            [
                (b"access-control-allow-methods", MCP_ALLOW_METHODS.encode("ascii")),
                (b"access-control-allow-headers", MCP_ALLOW_HEADERS.encode("ascii")),
                (b"access-control-max-age", b"600"),
            ]
        )
    return pairs


def _bearer(scope: Scope) -> str | None:
    """Authorization bearer only. Cookies and forwarded access tokens are ignored."""
    for key, value in scope.get("headers") or []:
        if key.lower() != b"authorization":
            continue
        raw = value.decode("latin-1").strip()
        if raw.lower().startswith("bearer "):
            return raw[7:].strip() or None
        return None
    return None


def _jsonrpc_id(body: bytes) -> int | str | None:
    """Echo a short JSON-RPC id. Never echo something that could be a credential."""
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict) or "id" not in payload:
        return None
    ident = payload["id"]
    if isinstance(ident, bool) or ident is None:
        return None
    if isinstance(ident, int):
        return ident
    if (
        isinstance(ident, str)
        and len(ident) <= 128
        and "secops_pat_" not in ident
        and ident.count(".") < 2
    ):
        return ident
    return None


async def _read_body(receive: Receive) -> tuple[bytes, ReceiveFn, bool]:
    """Buffer the request body so a rejected call can still be answered.

    Returns ``(body, replay, overflow)``. ``replay`` presents that body to the
    downstream app exactly once.
    """
    chunks: list[bytes] = []
    total = 0
    overflow = False
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"") or b""
        total += len(chunk)
        if total > _MAX_BODY:
            overflow = True
        elif not overflow:
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    body = b"".join(chunks)
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return body, replay, overflow


async def _send_bytes(
    send: Send,
    status: int,
    body: bytes,
    headers: list[tuple[bytes, bytes]],
) -> None:
    payload_headers = list(headers)
    payload_headers.append((b"content-length", str(len(body)).encode("ascii")))
    await send({"type": "http.response.start", "status": status, "headers": payload_headers})
    await send({"type": "http.response.body", "body": body})


async def _send_json(
    send: Send,
    status: int,
    payload: dict,
    headers: list[tuple[bytes, bytes]],
) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    full = [(b"content-type", b"application/json"), (b"cache-control", b"no-store"), *headers]
    await _send_bytes(send, status, body, full)


def _unauthorized_body(ident: int | str | None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": ident,
        "error": {"code": -32001, "message": "unauthorized"},
    }


class McpHttpGuard:
    """Reject anonymous and unverifiable MCP calls with the discovery challenge.

    OPTIONS is answered before any credential check. A browser ``Origin`` that is
    not the app's own origin, ``SECOPS_CORS_ORIGINS``, or
    ``SECOPS_MCP_ALLOWED_ORIGINS`` is 403 and the body never contains the bearer.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        origin = _header(headers, "origin")
        allowed = origin_allowed(scope, origin)
        if not allowed:
            await _send_json(send, 403, {"error": "origin_not_allowed"}, [])
            return

        method = (scope.get("method") or "GET").upper()
        if method == "OPTIONS":
            await _send_bytes(send, 204, b"", _cors_pairs(origin, preflight=True))
            return

        body, replay, overflow = await _read_body(receive)
        ident = _jsonrpc_id(body) if not overflow else None
        cors = _cors_pairs(origin, preflight=False)
        if overflow:
            await _send_json(
                send,
                413,
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "request too large"}},
                cors,
            )
            return

        token = _bearer(scope)
        try:
            await ensure_http_credential(token)
        except McpAuthError:
            logger.info("mcp request rejected (%s)", "invalid" if token else "missing")
            challenge = [(b"www-authenticate", www_authenticate(scope, invalid_token=bool(token)).encode("latin-1"))]
            await _send_json(send, 401, _unauthorized_body(ident), [*challenge, *cors])
            return
        except Exception as exc:
            logger.warning("mcp credential check failed: %s", type(exc).__name__)
            await _send_json(
                send,
                503,
                {
                    "jsonrpc": "2.0",
                    "id": ident,
                    "error": {"code": -32000, "message": "authentication unavailable"},
                },
                cors,
            )
            return

        async def send_with_cors(message: Message) -> None:
            if message["type"] == "http.response.start":
                merged = list(message.get("headers") or [])
                merged.extend(cors)
                message = {**message, "headers": merged}
            await send(message)

        await self.app(scope, replay, send_with_cors)


def _prm_headers() -> dict[str, str]:
    return {
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "public, max-age=3600",
    }


async def protected_resource_metadata_route(request: Request) -> Response:
    """RFC 9728. Unauthenticated. GET and OPTIONS, both discovery paths."""
    if request.method == "OPTIONS":
        return Response(
            status_code=204,
            headers={
                **_prm_headers(),
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "Accept, Authorization",
                "Access-Control-Max-Age": "3600",
            },
        )
    return JSONResponse(protected_resource_document(request.scope), headers=_prm_headers())


async def redirect_to_canonical_mcp(request: Request) -> RedirectResponse:
    """``/mcp`` → ``/mcp/`` (308). The query string is preserved; the host is not rewritten."""
    target = MCP_CANONICAL_PATH
    if request.url.query:
        target = f"{MCP_CANONICAL_PATH}?{request.url.query}"
    return RedirectResponse(url=target, status_code=308)


class ApiCorsMiddleware:
    """SPA CORS for every path except MCP and OAuth discovery.

    Starlette's CORS middleware answers OPTIONS itself. MCP must answer OPTIONS
    before authentication, and the protected-resource document must send
    ``Access-Control-Allow-Origin: *``, so those paths skip this middleware.
    """

    def __init__(self, app: ASGIApp) -> None:
        from starlette.middleware.cors import CORSMiddleware

        self.app = app
        self._cors = CORSMiddleware(
            app,
            allow_origins=list(settings.cors_origins),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "http":
            path = scope.get("path") or ""
            if (
                path == "/mcp"
                or path.startswith("/mcp/")
                or path.startswith("/.well-known/oauth-protected-resource")
            ):
                await self.app(scope, receive, send)
                return
        await self._cors(scope, receive, send)


def install_oauth_discovery(app: FastAPI) -> None:
    """Register the 308 slash redirect and both protected-resource documents.

    Call this before ``app.mount("/mcp", ...)`` so bare ``/mcp`` matches the
    redirect rather than the mount.
    """
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    app.add_api_route(
        "/mcp",
        redirect_to_canonical_mcp,
        methods=methods,
        include_in_schema=False,
    )
    for path in (PRM_PATH, "/.well-known/oauth-protected-resource/mcp", PRM_MCP_PATH):
        app.add_api_route(
            path,
            protected_resource_metadata_route,
            methods=["GET", "OPTIONS"],
            include_in_schema=False,
        )
