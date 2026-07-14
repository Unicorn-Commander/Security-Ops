from pathlib import Path

ROOT = Path(__file__).parents[1]
COMPOSE = (ROOT / "deploy/scanner-1/docker-compose.scanner.yml").read_text()


def test_scanner_is_opt_in_and_unpublished():
    assert "profiles: [scanner-pre-ga]" in COMPOSE
    active = "\n".join(line for line in COMPOSE.splitlines() if not line.lstrip().startswith("#"))
    assert "published:" not in active and "0.0.0.0:" not in active


def test_scanner_secrets_are_file_based():
    assert "SECOPS_DB_PASSWORD_FILE" in COMPOSE
    assert "SECOPS_APP_PASSWORD:?" not in COMPOSE
    assert "SECOPS_INTERNAL_LITELLM_API_KEY_FILE" in COMPOSE


def test_rollback_requires_explicit_approval():
    script = (ROOT / "scripts/scanner-host-rollback.sh").read_text()
    assert "SCANNER_ROLLBACK_APPROVED" in script and '== "YES"' in script


def test_scanner_env_template_enforces_queue_mode():
    env_template = (ROOT / "deploy/scanner-1/.env.scanner-1.example").read_text()
    assert "SECOPS_RUN_DISPATCH_MODE=queue" in env_template
    assert "SECOPS_RUN_DISPATCH_MODE=inline" not in env_template


def test_scanner_env_template_sets_production_environment():
    env_template = (ROOT / "deploy/scanner-1/.env.scanner-1.example").read_text()
    assert "SECOPS_ENVIRONMENT=production" in env_template
    assert "SECOPS_ENVIRONMENT=development" not in env_template


def test_scanner_compose_no_inline_mode():
    assert "RUN_DISPATCH_MODE: \"queue\"" in COMPOSE or "RUN_DISPATCH_MODE: queue" in COMPOSE
    assert "RUN_DISPATCH_MODE: inline" not in COMPOSE


def test_scanner_compose_has_heartbeat_healthcheck():
    assert "heartbeat" in COMPOSE
    assert "healthcheck" in COMPOSE
    assert "start_period: 30s" in COMPOSE
    assert "interval: 30s" in COMPOSE


def test_scanner_compose_no_published_ports():
    lines = [ln for ln in COMPOSE.splitlines() if not ln.strip().startswith("#")]
    active = "\n".join(lines)
    assert "published:" not in active
    assert "ports:" not in active
    assert "0.0.0.0:" not in active


def test_scanner_compose_uses_no_new_privileges():
    assert "no-new-privileges:true" in COMPOSE


def test_scanner_compose_read_only_rootfs():
    assert "read_only: true" in COMPOSE


def test_runner_main_loop_imports():
    script = (ROOT / "app/runner/loop.py").read_text()
    assert "run_forever" in script
    assert "_claim_one" in script
    assert "_heartbeat" in script
    assert "RUN_DISPATCH_MODE" in script or "run_dispatch_mode" in script


def test_rollback_script_drains_before_down():
    script = (ROOT / "scripts/scanner-host-rollback.sh").read_text()
    assert "stop --time" in script
    assert "compose down" in script
    assert "post-rollback validation" in script
