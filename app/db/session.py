"""Async engine, session factory, and the FastAPI DB dependency.

``get_session`` is THE database dependency for the whole app. Repositories and
services own their transactions; this dependency never auto-commits — it rolls
back on error and always closes.
"""

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings
from app.db.base import Base

engine: AsyncEngine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    future=True,
)

async_session: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_session() -> AsyncIterator[AsyncSession]:
    """Yield a request-scoped ``AsyncSession``; roll back on error, close on exit.

    The caller (route/service) owns commits; nothing here commits implicitly.
    """
    async with async_session() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


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
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the engine's connection pool (called on app shutdown)."""
    await engine.dispose()
