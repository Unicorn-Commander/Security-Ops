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

    RLS teardown: on Postgres the request may have bound its connection to a
    tenant via the session-level ``app.current_org_id`` GUC (see ``app.db.rls``).
    The ``finally`` block resets it before the connection returns to the pool so
    no later request can inherit another tenant's context. The reset sequence is
    rollback → clear → commit: the rollback discards any uncommitted caller work
    (exactly what ``session.close()`` would have done, so semantics are
    unchanged) and ensures the follow-up commit persists ONLY the GUC reset —
    necessary because a session-level ``set_config`` is itself transactional and
    would be reverted if its enclosing transaction rolled back at close. The
    whole reset is wrapped so a teardown failure can never mask the request's
    real exception; ``app.db.rls`` is imported lazily to avoid an import cycle.
    """
    async with get_sessionmaker()() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            try:
                from app.db.rls import clear_org_context, is_postgres_session

                if is_postgres_session(session):
                    await session.rollback()
                    await clear_org_context(session)
                    await session.commit()
            except Exception:  # pragma: no cover — best-effort teardown only
                pass


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
