"""Naabu port-discovery parsing and runner behavior."""

from __future__ import annotations

import json
from pathlib import Path

from app.engine.naabu_runner import NaabuRunner
from app.engine.strix_runner import StrixInvocation
from app.models.finding import FindingSeverity


def _write_jsonl(tmp_path: Path, rows: list[dict], name: str = "naabu.0.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


def test_naabu_runner_emits_one_finding_per_open_port(tmp_path: Path):
    _write_jsonl(
        tmp_path,
        [
            {"host": "example.com", "ip": "93.184.216.34", "port": 443},
            {"host": "example.com", "ip": "93.184.216.34", "port": 8443},
        ],
    )
    runner = NaabuRunner(session=None)  # type: ignore[arg-type]
    inv = StrixInvocation(
        run_dir=tmp_path,
        instruction_path=tmp_path / "scope.txt",
        model="naabu",
        verify_model="naabu",
        profile_name="naabu",
        env={},
        command=[],
        log_path=tmp_path / "naabu.stdout.log",
        pid_path=tmp_path / "naabu.pid",
    )
    result = runner._build_result(inv, returncode=0, error=None, stopped=False)

    assert len(result.findings) == 2
    assert result.findings[0].severity == FindingSeverity.INFO
    assert result.findings[0].title == "Open port 443/tcp on example.com"
    assert result.findings[0].endpoint == "example.com:443"
    assert result.findings[0].evidence["engine"] == "naabu"
    assert result.findings[0].evidence["confidence"] == "high"
