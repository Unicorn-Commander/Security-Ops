"""Shared test fixtures for the Security-Ops unit suite.

The suite runs against an in-memory aiosqlite database — the models declare
portable ``JSON``/``Uuid`` variants (PostgreSQL uses JSONB/native UUID, SQLite the
generic types), so the whole ORM boots without a container. Environment is set
BEFORE any ``app.*`` import so the lazy settings singleton materializes against
test config, never a developer's real ``.env``.

The crown-jewel fixture is :func:`db_session`: a real ``AsyncSession`` bound to a
freshly-created schema, handed straight to the authorization gate so the tests
exercise the actual enforcement path (not a mock).
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

# --- Test environment (must precede any app import) -------------------------
os.environ.setdefault("SECOPS_ENVIRONMENT", "development")
os.environ.setdefault("SECOPS_AUTH_BYPASS", "true")
os.environ.setdefault("SECOPS_DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("SECOPS_KEYCLOAK_ISSUER", "https://auth.test/realms/uchub")
os.environ.setdefault("SECOPS_KEYCLOAK_CLIENT_ID", "security-ops")
os.environ.setdefault("SECOPS_ATTESTATION_SKIP_LIVE_PROOF", "true")

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  — populate Base.metadata with every table
from app.db.base import Base
from app.models.engagement import Engagement, EngagementStatus
from app.models.organization import Organization
from app.models.target import (
    AttestationMethod,
    AttestationStatus,
    AuthorizedTarget,
    TargetKind,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest_asyncio.fixture(autouse=True)
async def _reset_global_engine():
    """Dispose + reset the app's lazily-cached global engine after every test.

    A test that drives the real ``app.db.session.get_session`` (e.g. the RLS
    teardown test) builds the process-wide ``_engine`` bound to *this* test's
    function-scoped event loop. Without disposal the aiosqlite worker thread
    lingers (the process hangs at exit) and the engine would be reused from a
    now-dead loop by a later test. Resetting the module globals gives each test a
    clean slate; disposal happens inside the still-open loop.
    """
    yield
    import app.db.session as s

    if s._engine is not None:
        await s.close_db()
        s._engine = None
        s._session_factory = None


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    """A function-scoped ``AsyncSession`` on a fresh in-memory schema.

    Uses a ``StaticPool`` so the single in-memory connection is shared for the
    fixture's lifetime (a new connection would see an empty database). Tables are
    created up-front and the engine disposed on teardown.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


# ---------------------------------------------------------------------------
# Builders — construct valid, gate-relevant rows with sensible defaults.
# ---------------------------------------------------------------------------
async def make_org(session: AsyncSession, *, slug: str = "pilot") -> Organization:
    org = Organization(id=uuid.uuid4(), slug=slug, name=f"{slug} org")
    session.add(org)
    await session.flush()
    return org


async def make_target(
    session: AsyncSession,
    org: Organization,
    *,
    value: str = "example.com",
    kind: TargetKind = TargetKind.DOMAIN,
    status: AttestationStatus = AttestationStatus.ATTESTED,
    method: AttestationMethod = AttestationMethod.OWNED,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> AuthorizedTarget:
    """A registered target, attested-and-valid by default. Pass ``status`` /
    ``expires_at`` / ``revoked_at`` to build the denial variants."""
    target = AuthorizedTarget(
        id=uuid.uuid4(),
        org_id=org.id,
        kind=kind,
        value=value,
        attestation_status=status,
        attestation_method=method,
        attested_by="tester",
        attested_at=utcnow() if status == AttestationStatus.ATTESTED else None,
        expires_at=expires_at,
        revoked_at=revoked_at,
    )
    session.add(target)
    await session.flush()
    return target


async def make_engagement(
    session: AsyncSession,
    org: Organization,
    *,
    in_scope: list[dict] | None = None,
    exclusions: list[dict] | None = None,
    status: EngagementStatus = EngagementStatus.ACTIVE,
    expires_at: datetime | None = None,
    rules_of_engagement: dict | None = None,
    emergency_stopped: bool = False,
) -> Engagement:
    """An ACTIVE engagement scoped to ``example.com`` by default."""
    engagement = Engagement(
        id=uuid.uuid4(),
        org_id=org.id,
        name="pilot engagement",
        status=status,
        scope={
            "in_scope": in_scope if in_scope is not None else [{"kind": "DOMAIN", "value": "example.com"}],
            "exclusions": exclusions or [],
        },
        rules_of_engagement=rules_of_engagement or {},
        model_profile="hybrid-local-sweep-verify",
        created_by="tester",
        expires_at=expires_at if expires_at is not None else utcnow() + timedelta(days=7),
        emergency_stopped=emergency_stopped,
    )
    session.add(engagement)
    await session.flush()
    return engagement
