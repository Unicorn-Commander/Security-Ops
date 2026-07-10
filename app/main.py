"""FastAPI composition root for Security-Ops.

Lifespan configures logging, initializes the DB, and disposes it on shutdown.
Installs the uniform error envelope + CORS and mounts the aggregate API router.
Also serves ``/health`` and ``/version`` directly so the container liveness
probe works even before optional sibling modules are wired in.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.core.config import settings
from app.db.session import close_db, get_engine, init_db

APP_TITLE = "Security-Ops API"
APP_VERSION = "0.5.0"

logger = logging.getLogger("secops")

# --- Optional sibling wiring -------------------------------------------------
# backend-core boots on its own. These modules are delivered by other blueprint
# modules (core.logging, core.errors, api.router). They are wired in
# automatically once present, and their absence never blocks startup.
try:
    from app.core.logging import configure_logging
except ImportError:  # pragma: no cover - sibling module optional in this slice

    def configure_logging() -> None:
        logging.basicConfig(
            level=logging.INFO,
            format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
        )


try:
    from app.core.errors import install_exception_handlers
except ImportError:  # pragma: no cover - sibling module optional in this slice
    install_exception_handlers = None

try:
    from app.api.router import api_router
except ImportError:  # pragma: no cover - sibling module optional in this slice
    api_router = None

# The agent-first MCP server (FastMCP over streamable-HTTP). Mounted at ``/mcp/``.
# Optional/guarded like the rest: if the ``mcp`` SDK is unavailable the app still
# boots the HTTP surface. Its session manager is run from the app lifespan below.
try:
    from app.mcp.server import mcp as mcp_server, mcp_asgi_app
except ImportError:  # pragma: no cover - mcp SDK optional in this slice
    mcp_server = None
    mcp_asgi_app = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    configure_logging()
    logger.info("security-ops starting (environment=%s)", settings.environment)
    await init_db()
    try:
        if mcp_server is not None:
            # The mounted MCP app's streamable-HTTP session manager must run for the
            # lifetime of the process (Starlette does not run a mounted sub-app's
            # own lifespan). Nest it inside our lifespan so both are managed.
            async with mcp_server.session_manager.run():
                yield
        else:  # pragma: no cover - only when the mcp SDK is absent
            yield
    finally:
        await close_db()
        logger.info("security-ops shutdown complete")


app = FastAPI(title=APP_TITLE, version=APP_VERSION, lifespan=lifespan)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

if install_exception_handlers is not None:
    install_exception_handlers(app)

if api_router is not None:
    app.include_router(api_router)
else:  # pragma: no cover - api module lands in a sibling slice
    logger.warning("app.api.router not importable yet; serving core routes only")

# Mount the agent-first MCP server at ``/mcp/`` (trailing slash). Every MCP call
# authenticates (PAT or JWT), enforces the ``security-ops`` entitlement, and scopes
# to the caller's org under RLS — identical guardrails to the HTTP surface.
if mcp_asgi_app is not None:
    app.mount("/mcp", mcp_asgi_app())
else:  # pragma: no cover - only when the mcp SDK is absent
    logger.warning("app.mcp.server not importable; MCP agent surface disabled")


async def _db_ok() -> bool:
    try:
        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        logger.exception("database health check failed")
        return False


@app.get("/health", tags=["health"])
async def health() -> dict:
    """Liveness + DB readiness probe."""
    return {"status": "ok", "version": APP_VERSION, "db": await _db_ok()}


@app.get("/version", tags=["health"])
async def version() -> dict:
    return {"version": APP_VERSION, "environment": settings.environment}
