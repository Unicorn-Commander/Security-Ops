"""Import, mapper, API, and migration wiring guards.

These tests fail at collection/configuration time instead of allowing a healthy
``/health`` response to hide a broken ORM registry, unmounted API, or migration
chain.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import configure_mappers

import app.api as api_pkg
import app.models  # noqa: F401 — registers every mapped class on Base
from app.db.base import Base


def test_all_mappers_configure() -> None:
    """Every relationship's ``back_populates`` target exists."""
    configure_mappers()


def test_api_router_imports() -> None:
    """``app.api.router`` imports strictly and exposes the versioned prefix."""
    module = importlib.import_module("app.api.router")
    assert module.api_router.prefix == "/api/v1"


def test_every_api_module_router_is_mounted() -> None:
    """Every API module with a router is included in the composition router."""
    from app.api.router import api_router

    mounted = {getattr(route, "endpoint", None) for route in api_router.routes}
    missing: list[str] = []
    for info in pkgutil.iter_modules(api_pkg.__path__):
        if info.name in {"router", "deps"}:
            continue
        module = importlib.import_module(f"app.api.{info.name}")
        sub_router = getattr(module, "router", None)
        if sub_router is None:
            continue
        if not any(
            getattr(route, "endpoint", None) in mounted for route in sub_router.routes
        ):
            missing.append(info.name)
    assert not missing, f"app.api modules with an unmounted router: {missing}"


def test_app_mounts_the_api_surface() -> None:
    """The composition root mounts the versioned API and health route."""
    from app.main import app

    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/v1/overview" in paths, sorted(paths)
    assert "/health" in paths


def _migration_ddl_text() -> str:
    """Concatenate migration source, the DDL text that builds the schema."""
    root = Path(__file__).resolve().parents[1] / "migrations" / "versions"
    return "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(root.glob("*.py"))
    )


def test_alembic_single_head() -> None:
    """A branched migration history breaks ``alembic upgrade head``."""
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert heads == ["0014_task1_through_6"]


def test_every_mapped_table_and_column_has_a_migration() -> None:
    """Guard against models getting ahead of the migration chain."""
    ddl = _migration_ddl_text()
    missing_tables: list[str] = []
    missing_columns: list[str] = []
    for table in Base.metadata.sorted_tables:
        if f'"{table.name}"' not in ddl and f"'{table.name}'" not in ddl:
            missing_tables.append(table.name)
            continue
        for column in table.columns:
            if f'"{column.name}"' not in ddl and f"'{column.name}'" not in ddl:
                missing_columns.append(f"{table.name}.{column.name}")
    assert not missing_tables, f"mapped tables absent from migrations: {missing_tables}"
    assert not missing_columns, (
        f"mapped columns absent from migrations: {missing_columns}"
    )


def test_0014_reconciles_an_existing_0014_schema() -> None:
    """Applying 0014 twice does not duplicate its tables or columns."""
    migration = importlib.import_module("migrations.versions.0014_task1_through_6")
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE organizations (id CHAR(32) PRIMARY KEY)"
        )
        connection.exec_driver_sql("CREATE TABLE engagements (id CHAR(32) PRIMARY KEY)")
        connection.exec_driver_sql("CREATE TABLE runs (id CHAR(32) PRIMARY KEY)")
        connection.exec_driver_sql("CREATE TABLE findings (id CHAR(32) PRIMARY KEY)")

        context = MigrationContext.configure(connection)
        from alembic.operations import Operations

        with Operations.context(context):
            migration.upgrade()
            migration.upgrade()

        inspector = inspect(connection)
        assert {"finding_remediations", "scheduled_scans"} <= set(
            inspector.get_table_names()
        )
        assert "max_concurrent_runs" in {
            column["name"] for column in inspector.get_columns("organizations")
        }
        assert "max_execution_time" in {
            column["name"] for column in inspector.get_columns("runs")
        }
        result = connection.execute(
            text("SELECT COUNT(*) FROM scheduled_scans")
        ).scalar_one()
        assert result == 0
