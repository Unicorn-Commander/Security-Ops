"""app.engine.naabu_runner — the Naabu engine (port discovery).

Rides the existing DOMAIN + IP_RANGE target kinds and emits one INFO finding per
open port.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.engine.strix_runner import (
    ParsedVulnerability,
    StrixInvocation,
    StrixRunResult,
    StrixRunner,
    resolve_model_profile,
)
from app.models.finding import FindingSeverity

if TYPE_CHECKING:  # pragma: no cover
    from app.models.engagement import Engagement
    from app.models.run import Run

NAABU_BIN = "naabu"


class NaabuRunner(StrixRunner):
    """Naabu engine — port discovery behind the authorization gate."""

    def prepare(
        self,
        *,
        run: "Run",
        engagement: "Engagement",
        scope_mode: str | None = None,
        diff_base: str | None = None,
    ) -> StrixInvocation:
        run_dir = Path(self.settings.runs_dir) / str(run.id)
        run_dir.mkdir(parents=True, exist_ok=True)

        scope_note = run_dir / "scope.txt"
        try:
            scope_note.write_text(
                "Authorized Naabu scan. Targets are gate-cleared:\n"
                + "\n".join(f"- {t}" for t in (run.targets or [])),
                encoding="utf-8",
            )
        except OSError:  # pragma: no cover
            pass

        command = _build_naabu_command(run.targets or [], run_dir)
        verify_model = resolve_model_profile(getattr(run, "model_profile", None)).verify
        return StrixInvocation(
            run_dir=run_dir,
            instruction_path=scope_note,
            model="naabu",
            verify_model=verify_model,
            profile_name="naabu",
            env=dict(os.environ),
            command=command,
            log_path=run_dir / "naabu.stdout.log",
            pid_path=run_dir / "naabu.pid",
        )

    def _build_result(
        self,
        invocation: StrixInvocation,
        *,
        returncode: int | None,
        error: str | None,
        stopped: bool,
    ) -> StrixRunResult:
        findings: list[ParsedVulnerability] = []
        for path in sorted(invocation.run_dir.glob("naabu.*.jsonl")):
            findings.extend(_parse_naabu_jsonl(path))
        report_present = any(p.exists() for p in invocation.run_dir.glob("naabu.*.jsonl"))
        return StrixRunResult(
            returncode=returncode,
            findings=findings,
            metadata={
                "engine": "naabu",
                "returncode": returncode,
                "finding_count": len(findings),
                "report_present": report_present,
            },
            report_path=None,
            error=error,
            stopped=stopped,
        )

    def _engine_completed(self, result: StrixRunResult) -> bool:
        return result.returncode == 0


def _build_naabu_command(targets: list[str], run_dir: Path) -> list[str]:
    lines = ["set +e"]
    for i, target in enumerate(targets):
        report = run_dir / f"naabu.{i}.jsonl"
        tq = shlex.quote(str(target))
        rq = shlex.quote(str(report))
        lines.append(f"{NAABU_BIN} -host {tq} -json -o {rq} -silent || true")
    return ["bash", "-c", "\n".join(lines)]


def _parse_naabu_jsonl(path: Path | str) -> list[ParsedVulnerability]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return []
    findings: list[ParsedVulnerability] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        findings.append(_vuln_from_naabu(item))
    return findings


def _vuln_from_naabu(item: dict[str, Any]) -> ParsedVulnerability:
    host = str(item.get("host") or item.get("ip") or item.get("hostip") or "").strip()
    port = item.get("port")
    endpoint = f"{host}:{port}" if host and port is not None else host or None
    title = f"Open port {port}/tcp on {host}" if host and port is not None else "Open port"
    evidence = {
        "engine": "naabu",
        "confidence": "high",
        "host": host or None,
        "ip": item.get("ip"),
        "port": port,
        "raw": item,
    }
    return ParsedVulnerability(
        title=title,
        severity=FindingSeverity.INFO,
        cwe=None,
        endpoint=endpoint,
        payload=None,
        poc=None,
        evidence={k: v for k, v in evidence.items() if v is not None or k == "raw"},
        raw=item,
    )
