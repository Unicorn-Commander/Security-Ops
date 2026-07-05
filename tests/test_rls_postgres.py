"""Org-level Postgres RLS — integration proof + sqlite no-op safety.

Two halves, matching the two backends the app runs on:

1. **Postgres integration test** (the real proof) — gated on the
   ``SECOPS_TEST_DATABASE_URL`` env var pointing at a PostgreSQL URL. It builds
   the schema, applies the *exact* DDL from migration ``0002_org_rls`` (loaded
   from the migration file itself so the test can never drift from what ships),
   seeds two orgs with engagements/runs/findings/targets, and asserts:

   * context = org A → only A's rows visible (per table);
   * context = org B → only B's rows visible;
   * context cleared/absent → ZERO rows (fail-closed default);
   * WITH CHECK: with context A, INSERTing a row stamped ``org_id = B`` is
     rejected by the database.

   In CI (no Postgres) this half SKIPS — expected and correct. To run it
   locally::

       SECOPS_TEST_DATABASE_URL=postgresql+asyncpg://secops:...@localhost/secops_rls_test \
           python3 -m pytest tests/test_rls_postgres.py

   ⚠️ The URL's role must NOT be a superuser or hold BYPASSRLS — those bypass
   RLS entirely (FORCE only covers the plain table owner) and every isolation
   assertion would fail. A plain database-owner role is fine.

2. **sqlite no-op tests** — always run. ``set_org_context`` /
   ``clear_org_context`` must be silent no-ops off Postgres (sqlite has no
   ``set_config``), so the request path that now calls them stays green on the
   default container-free unit suite.

Pool note: the Postgres engine is created with ``pool_size=1, max_overflow=0``
so every checkout reuses the one physical connection — that makes the
session-level-GUC-survives-commit property (the reason ``set_config`` uses
``is_local=false``) directly observable across the intra-test commits.
"""

from __future__ import annotations

import importlib.util
import os
import uuid
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.rls import clear_org_context, is_postgres_session, set_org_context
from app.models.engagement import Engagement, EngagementStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.organization import Organization
from app.models.run import Run, RunMode, RunStatus
from app.models.target import AttestationStatus, AuthorizedTarget, TargetKind

# ---------------------------------------------------------------------------
# Postgres gate
# ---------------------------------------------------------------------------
POSTGRES_URL = os.environ.get("SECOPS_TEST_DATABASE_URL", "")

requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL.startswith("postgresql"),
    reason=(
        "SECOPS_TEST_DATABASE_URL is not set to a PostgreSQL URL — the RLS "
        "integration test needs a live Postgres (role without BYPASSRLS)"
    ),
)

_MIGRATION_0002 = (
    Path(__file__).resolve().parent.parent / "migrations" / "versions" / "0002_org_rls.py"
)


def _load_rls_migration():
    """Import ``migrations/versions/0002_org_rls.py`` by path.

    Migration files live outside the ``app`` package, so they are loaded via
    importlib. Reusing the migration's own ``_upgrade_statements()`` keeps this
    test byte-identical to the DDL that ships.
    """
    spec = importlib.util.spec_from_file_location("secops_migration_0002", _MIGRATION_0002)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Seed builders (Postgres half) — one full org tree per tenant.
# ---------------------------------------------------------------------------
def _org_tree(slug: str) -> tuple[Organization, AuthorizedTarget, Engagement, Run, Finding]:
    """A full tenant tree (org → target/engagement → run → finding), unstamped
    into any session yet. Every child row carries the org's id."""
    org = Organization(id=uuid.uuid4(), slug=slug, name=f"{slug} org")
    target = AuthorizedTarget(
        id=uuid.uuid4(),
        org_id=org.id,
        kind=TargetKind.DOMAIN,
        value=f"{slug}.example.com",
        attestation_status=AttestationStatus.UNATTESTED,
    )
    engagement = Engagement(
        id=uuid.uuid4(),
        org_id=org.id,
        name=f"{slug} engagement",
        status=EngagementStatus.ACTIVE,
        scope={"in_scope": [{"kind": "DOMAIN", "value": f"{slug}.example.com"}], "exclusions": []},
        rules_of_engagement={},
        created_by="rls-test",
    )
    run = Run(
        id=uuid.uuid4(),
        engagement_id=engagement.id,
        org_id=org.id,
        mode=RunMode.QUICK,
        model_profile="hybrid-local-sweep-verify",
        targets=[f"{slug}.example.com"],
        status=RunStatus.COMPLETED,
    )
    finding = Finding(
        id=uuid.uuid4(),
        run_id=run.id,
        engagement_id=engagement.id,
        org_id=org.id,
        title=f"{slug} secret finding",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.NEW,
    )
    return org, target, engagement, run, finding


async def _visible_ids(session: AsyncSession, model) -> set[uuid.UUID]:
    return set((await session.execute(select(model.id))).scalars().all())


# ---------------------------------------------------------------------------
# Postgres integration test (SKIPS without SECOPS_TEST_DATABASE_URL)
# ---------------------------------------------------------------------------
@requires_postgres
async def test_org_rls_isolates_tenants_on_postgres():
    migration = _load_rls_migration()
    # pool_size=1 → one physical connection for the whole test, so the
    # session-level GUC observably survives the commits below.
    engine = create_async_engine(POSTGRES_URL, pool_size=1, max_overflow=0)
    tenant_models = (AuthorizedTarget, Engagement, Run, Finding)
    try:
        # Fresh schema + the exact shipped RLS DDL.
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
            for statement in migration._upgrade_statements():
                await conn.execute(text(statement))

        factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        org_a, target_a, eng_a, run_a, finding_a = _org_tree("rls-org-a")
        org_b, target_b, eng_b, run_b, finding_b = _org_tree("rls-org-b")
        # Snapshot the (client-generated) ids as plain uuids NOW: the rollback
        # below expires every in-session instance, and touching an expired
        # attribute on an AsyncSession object raises MissingGreenlet.
        org_a_id, org_b_id = org_a.id, org_b.id
        a_ids = (target_a.id, eng_a.id, run_a.id, finding_a.id)
        b_ids = (target_b.id, eng_b.id, run_b.id, finding_b.id)

        async with factory() as session:
            assert is_postgres_session(session)

            # Seed. Orgs first (organizations is unpoliced); each tenant's
            # children only pass WITH CHECK under their own context.
            session.add_all([org_a, org_b])
            await session.commit()

            await set_org_context(session, org_a_id)
            session.add_all([target_a, eng_a, run_a, finding_a])
            await session.commit()  # session-level GUC survives this commit

            await set_org_context(session, org_b_id)
            session.add_all([target_b, eng_b, run_b, finding_b])
            await session.commit()

            # --- Context A: exactly A's rows, B invisible -------------------
            await set_org_context(session, org_a_id)
            for model, a_id in zip(tenant_models, a_ids):
                assert await _visible_ids(session, model) == {a_id}
            # organizations is intentionally unpoliced (slug-lookup bootstrap).
            assert {org_a_id, org_b_id} <= await _visible_ids(session, Organization)
            await session.commit()  # pin GUC=A for the rollback below

            # --- WITH CHECK: cannot write another org's rows ----------------
            smuggled = Finding(
                id=uuid.uuid4(),
                run_id=b_ids[2],
                engagement_id=b_ids[1],
                org_id=org_b_id,  # stamped B while context is A
                title="cross-tenant smuggle attempt",
                severity=FindingSeverity.CRITICAL,
                status=FindingStatus.NEW,
            )
            session.add(smuggled)
            with pytest.raises(DBAPIError):  # "violates row-level security policy"
                await session.flush()
            await session.rollback()  # GUC reverts to last committed value (A)

            # --- Context B: the mirror image --------------------------------
            await set_org_context(session, org_b_id)
            for model, b_id in zip(tenant_models, b_ids):
                assert await _visible_ids(session, model) == {b_id}

            # --- Cleared context: fail-closed, zero rows everywhere ---------
            await clear_org_context(session)
            for model in tenant_models:
                count = (
                    await session.execute(select(func.count()).select_from(model))
                ).scalar_one()
                assert count == 0, f"{model.__tablename__} leaked rows with no org context"
            await session.commit()  # persist the cleared GUC on the connection

        # --- Brand-new session, no context ever set: still zero rows --------
        async with factory() as session:
            for model in tenant_models:
                count = (
                    await session.execute(select(func.count()).select_from(model))
                ).scalar_one()
                assert count == 0, f"{model.__tablename__} visible without org context"
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


# ---------------------------------------------------------------------------
# sqlite half — always runs; proves the request-path wiring is harmless there.
# ---------------------------------------------------------------------------
async def test_rls_helpers_are_noops_on_sqlite(db_session):
    """set/clear_org_context must be silent no-ops on sqlite.

    ``get_current_org`` and ``get_session`` now call these on every request;
    the default (container-free) suite runs on sqlite, so they must neither
    error nor emit ``set_config`` (which sqlite lacks).
    """
    assert not is_postgres_session(db_session)

    org = Organization(id=uuid.uuid4(), slug="rls-noop", name="rls noop org")
    db_session.add(org)
    await db_session.flush()

    await set_org_context(db_session, org.id)
    await clear_org_context(db_session)
    await set_org_context(db_session, org.id)

    # The session is still healthy and (sqlite = no RLS) rows stay visible.
    fetched = (
        await db_session.execute(select(Organization).where(Organization.slug == "rls-noop"))
    ).scalar_one()
    assert fetched.id == org.id


async def test_get_session_teardown_resets_cleanly_on_sqlite():
    """The get_session finally-block (RLS reset) must not disturb sqlite flows.

    Drives the real dependency generator end-to-end against the test database
    and asserts both the success path and the error path (which must re-raise
    the ORIGINAL exception, never a teardown artifact).
    """
    from app.db.session import get_session

    # Success path: session usable, generator closes without error.
    agen = get_session()
    session = await anext(agen)
    assert (await session.execute(select(1))).scalar_one() == 1
    with pytest.raises(StopAsyncIteration):
        await anext(agen)

    # Error path: the thrown exception propagates unmasked.
    agen = get_session()
    await anext(agen)

    class Boom(RuntimeError):
        pass

    with pytest.raises(Boom):
        await agen.athrow(Boom("original request failure"))
