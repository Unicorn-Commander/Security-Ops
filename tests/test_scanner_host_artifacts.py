"""Check the optional scanner-host bundle when it is present in this branch."""

from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def _read_optional_artifact(relative_path):
    path = ROOT / relative_path
    if not path.is_file():
        pytest.skip(f"optional scanner-host artifact is absent: {relative_path}")
    return path.read_text()


@pytest.fixture(scope="module")
def compose():
    return _read_optional_artifact("deploy/scanner-1/docker-compose.scanner.yml")


def test_scanner_is_opt_in_and_unpublished(compose):
    assert "profiles: [scanner-pre-ga]" in compose
    active = "\n".join(
        line for line in compose.splitlines() if not line.lstrip().startswith("#")
    )
    assert "published:" not in active and "0.0.0.0:" not in active


def test_scanner_secrets_are_file_based(compose):
    assert "SECOPS_DB_PASSWORD_FILE" in compose
    assert "SECOPS_APP_PASSWORD:?" not in compose
    assert "SECOPS_INTERNAL_LITELLM_API_KEY_FILE" in compose


def test_rollback_requires_explicit_approval():
    script = (ROOT / "scripts/scanner-host-rollback.sh").read_text()
    assert "SCANNER_ROLLBACK_APPROVED" in script and '== "YES"' in script


def test_scanner_env_template_enforces_queue_mode():
    env_template = _read_optional_artifact("deploy/scanner-1/.env.scanner-1.example")
    assert "SECOPS_RUN_DISPATCH_MODE=queue" in env_template
    assert "SECOPS_RUN_DISPATCH_MODE=inline" not in env_template


def test_scanner_env_template_sets_production_environment():
    env_template = _read_optional_artifact("deploy/scanner-1/.env.scanner-1.example")
    assert "SECOPS_ENVIRONMENT=production" in env_template
    assert "SECOPS_ENVIRONMENT=development" not in env_template


def test_scanner_compose_no_inline_mode(compose):
    assert (
        'RUN_DISPATCH_MODE: "queue"' in compose or "RUN_DISPATCH_MODE: queue" in compose
    )
    assert "RUN_DISPATCH_MODE: inline" not in compose


def test_scanner_compose_has_heartbeat_healthcheck(compose):
    assert "heartbeat" in compose
    assert "healthcheck" in compose
    assert "start_period: 30s" in compose
    assert "interval: 30s" in compose


def test_scanner_compose_no_published_ports(compose):
    lines = [ln for ln in compose.splitlines() if not ln.strip().startswith("#")]
    active = "\n".join(lines)
    assert "published:" not in active
    assert "ports:" not in active
    assert "0.0.0.0:" not in active


def test_scanner_compose_uses_no_new_privileges(compose):
    assert "no-new-privileges:true" in compose


def test_scanner_compose_read_only_rootfs(compose):
    assert "read_only: true" in compose


def test_runner_main_loop_imports():
    script = (ROOT / "app/runner/loop.py").read_text()
    assert "run_forever" in script
    assert "_claim_one" in script
    assert "RUN_DISPATCH_MODE" in script or "run_dispatch_mode" in script


def test_rollback_script_drains_before_down():
    script = (ROOT / "scripts/scanner-host-rollback.sh").read_text()
    assert "stop --time" in script
    assert "compose down" in script
    assert "post-rollback validation" in script
