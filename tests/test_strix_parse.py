"""Strix 1.0.4 output parsing — the nested-output-dir contract.

Strix >=1.0 writes its artifacts into a NESTED ``strix_runs/<target>_<hash>/``
subdir of the run dir, not the run dir itself. These tests pin that resolution
(the bug that made every real run read 0 findings / cost=None / report=None) using
the exact shapes a live ``strix-agent==1.0.4`` run produced against OWASP Juice
Shop, plus the flat-layout fallback so fixtures/older callers keep working.
"""

from __future__ import annotations

import json

from app.engine.strix_runner import (
    _report_path,
    _strix_output_dir,
    parse_run_metadata,
    parse_vulnerabilities,
)
from app.models.finding import FindingSeverity

# The real vulnerabilities.json a gpt-5.4-mini QUICK run wrote for Juice Shop.
_REAL_VULNS = [
    {
        "id": "vuln-0001",
        "title": "Insecure Direct Object Reference in user profile API",
        "severity": "medium",
        "timestamp": "2026-07-07 06:21:04 UTC",
        "description": "The user profile API returns arbitrary user records when supplied with a numeric user ID.",
        "impact": "An attacker with any valid account can enumerate users and obtain account metadata.",
        "target": "http://host.docker.internal:3000",
        "technical_analysis": "The endpoint /api/Users/{id} does not enforce object ownership.",
    }
]
# The real run.json shape: Strix's OWN terminal status is "completed".
_REAL_RUN_JSON = {
    "run_id": "host-docker-internal-3000_8b33",
    "status": "completed",
    "start_time": "2026-07-07T06:20:15+00:00",
    "end_time": "2026-07-07T06:21:17+00:00",
    "llm_usage": {"requests": 30, "input_tokens": 1032115, "output_tokens": 6600},
}


def _nested(run_dir, target="host-docker-internal-3000_8b33"):
    """Build the real Strix 1.0.4 nested layout under ``run_dir`` and return it."""
    out = run_dir / "strix_runs" / target
    out.mkdir(parents=True)
    (out / "vulnerabilities.json").write_text(json.dumps(_REAL_VULNS), encoding="utf-8")
    (out / "run.json").write_text(json.dumps(_REAL_RUN_JSON), encoding="utf-8")
    (out / "penetration_test_report.md").write_text("# Report\n", encoding="utf-8")
    return out


def test_output_dir_resolves_nested(tmp_path):
    out = _nested(tmp_path)
    assert _strix_output_dir(tmp_path) == out


def test_output_dir_falls_back_to_flat(tmp_path):
    # No strix_runs/ subdir (flat fixture layout) -> use run_dir itself.
    (tmp_path / "vulnerabilities.json").write_text("[]", encoding="utf-8")
    assert _strix_output_dir(tmp_path) == tmp_path


def test_parses_finding_from_nested_dir(tmp_path):
    _nested(tmp_path)
    findings = parse_vulnerabilities(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Insecure Direct Object Reference in user profile API"
    assert f.severity == FindingSeverity.MEDIUM
    assert f.endpoint == "http://host.docker.internal:3000"
    # The full item (impact, technical_analysis) is retained as evidence.
    assert f.evidence["raw"]["technical_analysis"].startswith("The endpoint /api/Users")


def test_run_metadata_reads_strix_status_from_nested(tmp_path):
    _nested(tmp_path)
    meta = parse_run_metadata(tmp_path)
    assert meta["strix_status"] == "completed"
    assert meta["strix_run_id"] == "host-docker-internal-3000_8b33"
    assert isinstance(meta["usage"], dict) and meta["usage"]["requests"] == 30


def test_report_path_resolves_nested(tmp_path):
    out = _nested(tmp_path)
    assert _report_path(tmp_path) == str(out / "penetration_test_report.md")


def test_empty_run_dir_is_tolerant(tmp_path):
    assert parse_vulnerabilities(tmp_path) == []
    assert parse_run_metadata(tmp_path)["strix_status"] is None
    assert _report_path(tmp_path) is None
