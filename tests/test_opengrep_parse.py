"""Opengrep parsing and runner behavior.

Pins the Semgrep-compatible JSON contract plus the runner-side evidence normalization
used by the Opengrep engine.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.engine.opengrep_runner import OpengrepRunner
from app.engine.strix_runner import StrixInvocation
from app.models.finding import FindingSeverity


def _write_json(tmp_path: Path, payload: dict, name: str = "opengrep.0.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_opengrep_runner_normalizes_check_id_and_confidence(tmp_path: Path):
    _write_json(
        tmp_path,
        {
            "results": [
                {
                    "check_id": "python.lang.security.eval",
                    "path": "src/app.py",
                    "start": {"line": 12},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Dangerous eval",
                        "metadata": {"cwe": "CWE-94"},
                    },
                }
            ]
        },
    )
    runner = OpengrepRunner(session=None)  # type: ignore[arg-type]
    inv = StrixInvocation(
        run_dir=tmp_path,
        instruction_path=tmp_path / "scope.txt",
        model="opengrep",
        verify_model="opengrep",
        profile_name="opengrep",
        env={},
        command=[],
        log_path=tmp_path / "opengrep.stdout.log",
        pid_path=tmp_path / "opengrep.pid",
    )
    result = runner._build_result(inv, returncode=0, error=None, stopped=False)

    assert result.findings[0].severity == FindingSeverity.HIGH
    assert result.findings[0].endpoint == "src/app.py:12"
    assert result.findings[0].evidence["engine"] == "opengrep"
    assert result.findings[0].evidence["rule"] == "python.lang.security.eval"
    assert result.findings[0].evidence["confidence"] == "medium"
