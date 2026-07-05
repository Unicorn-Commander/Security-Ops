"""Cleanup guarantee: the app package imports with NO environment configured.

Phase 1 instantiated settings + the DB engine at import, so a bare ``import
app.*`` (or a test collection) required the full runtime env. Phase 2 makes both
lazy. These tests pin that: the security-critical modules must import in a
subprocess whose environment has every ``SECOPS_*`` var stripped, and the DB
engine must not be constructed until first use.
"""

from __future__ import annotations

import os
import subprocess
import sys

# Modules that must import without touching settings/DB. (app.main is the ASGI
# composition root and legitimately needs config to build the app, so it is
# excluded here by design.)
_ENV_FREE_MODULES = [
    "app.core.config",
    "app.db.session",
    "app.authz.gate",
    "app.authz.attestation",
    "app.auth.entitlement",
    "app.auth.sso",
    "app.api.deps",
    "app.api.router",
    "app.services.runs",
    "app.engine.strix_runner",
    "app.engine.brigade_handoff",
]


def test_modules_import_without_env():
    """Import every core module in a subprocess with all SECOPS_* vars removed."""
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("SECOPS_")}
    # Also drop a bare DATABASE_URL alias so nothing sneaks config in.
    clean_env.pop("DATABASE_URL", None)
    clean_env["PYTHONPATH"] = os.getcwd()

    code = "import importlib, sys\n" + "".join(
        f"importlib.import_module({m!r})\n" for m in _ENV_FREE_MODULES
    ) + "print('OK')\n"

    result = subprocess.run(
        [sys.executable, "-c", code],
        env=clean_env,
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
    )
    assert result.returncode == 0, f"import failed:\n{result.stderr}"
    assert "OK" in result.stdout


def test_engine_not_built_until_first_use():
    """Importing app.db.session must not construct the engine eagerly."""
    import app.db.session as session_mod

    # _engine is module-private; it stays None until get_engine()/get_session() runs.
    # (This process has test env set, but the point is import-time laziness.)
    # We can't assert None globally because other tests may have built it, so run
    # the check in a clean subprocess.
    code = (
        "import app.db.session as s\n"
        "assert s._engine is None, 'engine built at import!'\n"
        "assert s._session_factory is None, 'sessionmaker built at import!'\n"
        "print('LAZY')\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.getcwd()
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, cwd=os.getcwd()
    )
    assert result.returncode == 0, result.stderr
    assert "LAZY" in result.stdout
    assert session_mod is not None  # import above succeeded
