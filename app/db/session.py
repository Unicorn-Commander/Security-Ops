"""Async engine, session factory, and the FastAPI DB dependency.

``get_session`` is THE database dependency for the whole app. Repositories and
services own their transactions; this dependency never auto-commits — it rolls
back on error and always closes.
"""

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings
from app.db.base import Base

# The engine + session factory are built LAZILY (on first use), not at import.
# A bare ``import app.db.session`` must not open a connection or require the DB
# URL to be configured — that keeps imports/tests cheap and env-free. The
# module-level ``engine`` / ``async_session`` names are still importable via
# ``__getattr__`` for backwards compatibility, but new code should call the
# accessors so it never forces eager construction at *its* import time.
_engine: AsyncEngine | None = None
_session_factory: "async_sessionmaker[AsyncSession] | None" = None


def get_engine() -> AsyncEngine:
    """Return the process-wide async engine, building it on first call."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            settings.database_url,
            pool_pre_ping=True,
            future=True,
        )
    return _engine


def get_sessionmaker() -> "async_sessionmaker[AsyncSession]":
    """Return the process-wide session factory, building it on first call."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


def __getattr__(name: str) -> Any:
    """Lazily materialize the legacy module-level ``engine`` / ``async_session``.

    ``from app.db.session import engine`` / ``async_session`` still works, but the
    engine is only constructed when the name is first accessed rather than at
    import — preserving env-free imports.
    """
    if name == "engine":
        return get_engine()
    if name == "async_session":
        return get_sessionmaker()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


async def get_session() -> AsyncIterator[AsyncSession]:
    """Yield a request-scoped ``AsyncSession``; roll back on error, close on exit.

    The caller (route/service) owns commits; nothing here commits implicitly.

    **RLS connection pinning (Postgres).** Tenant isolation binds the session-level
    GUC ``app.current_org_id`` to the connection (set by ``get_current_org`` via
    ``app.db.rls.set_org_context``). But a plain ``Session`` releases its connection
    back to the pool on every ``commit()`` — and services commit mid-request — so a
    later query could land on a *different* pooled connection that never received
    the ``SET``, and RLS would then silently return ZERO rows (or, worse, a stale
    tenant's). To close that window the whole request is pinned to ONE checked-out
    connection: the GUC therefore applies to every statement across all
    intra-request commits. On teardown the GUC is reset (rollback → clear → commit)
    before the connection returns to the pool so no later request inherits the
    context. Non-Postgres backends (the sqlite unit-test DB) have no RLS and take
    the simple unpinned path. ``app.db.rls`` is imported lazily to avoid a cycle.
    """
    engine = get_engine()
    if engine.dialect.name != "postgresql":
        async with get_sessionmaker()() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
        return

    from app.db.rls import clear_org_context  # lazy: avoid import cycle

    # Pin one connection for the request so the org GUC survives mid-request commits.
    async with engine.connect() as conn:
        session = get_sessionmaker()(bind=conn)
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            try:
                # rollback → clear → commit: discard any uncommitted caller work,
                # then persist ONLY the GUC reset (a session-level set_config is
                # itself transactional and would revert on a bare close()).
                await session.rollback()
                await clear_org_context(session)
                await session.commit()
            except Exception:  # pragma: no cover — best-effort teardown only
                pass
            finally:
                await session.close()


async def init_db() -> None:
    """Create schema in development; defer to Alembic in production.

    Importing ``app.models`` populates ``Base.metadata`` with every table before
    ``create_all`` runs. In production the container applies Alembic migrations
    at startup, so this is a no-op there.
    """
    if settings.environment != "development":
        return
    try:
        import app.models  # noqa: F401  (populate Base.metadata)
    except ImportError:
        # Model modules not present yet (partial checkout / core-only slice).
        pass
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the engine's connection pool (called on app shutdown)."""
    if _engine is not None:
        await _engine.dispose()
