"""OWASP ZAP parsing and runner behavior."""

from __future__ import annotations

import json
from pathlib import Path

from app.engine.strix_runner import StrixInvocation
from app.engine.zap_runner import ZapRunner
from app.models.finding import FindingSeverity


def _write_json(tmp_path: Path, payload: dict, name: str = "zap.0.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_zap_runner_normalizes_riskcode(tmp_path: Path):
    _write_json(
        tmp_path,
        {
            "site": [
                {
                    "@name": "example.com",
                    "alerts": [
                        {
                            "riskcode": "3",
                            "alert": "X-Frame-Options header not set",
                            "cweid": "1021",
                            "instances": [{"uri": "https://example.com/login"}],
                            "desc": "Missing clickjacking protection.",
                            "solution": "Set X-Frame-Options",
                        }
                    ],
                }
            ]
        },
    )
    runner = ZapRunner(session=None)  # type: ignore[arg-type]
    inv = StrixInvocation(
        run_dir=tmp_path,
        instruction_path=tmp_path / "scope.txt",
        model="zap",
        verify_model="zap",
        profile_name="zap",
        env={},
        command=[],
        log_path=tmp_path / "zap.stdout.log",
        pid_path=tmp_path / "zap.pid",
    )
    result = runner._build_result(inv, returncode=1, error=None, stopped=False)

    finding = result.findings[0]
    assert finding.severity == FindingSeverity.HIGH
    assert finding.endpoint == "https://example.com/login"
    assert finding.evidence["engine"] == "zap"
    assert finding.evidence["confidence"] == "medium"
