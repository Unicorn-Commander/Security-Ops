"""app.engine.opengrep_runner — the Opengrep engine (SAST, Semgrep-compatible).

Opengrep rides the existing REPO target kind and mirrors the Gitleaks repo-clone
pattern: materialize each target into the run dir, then invoke ``opengrep scan``
against the clone and normalize its JSON through the shared parser registry.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import TYPE_CHECKING

from app.engine.parsers import get_parser
from app.engine.strix_runner import (
    ParsedVulnerability,
    StrixInvocation,
    StrixRunResult,
    StrixRunner,
    resolve_model_profile,
)

if TYPE_CHECKING:  # pragma: no cover
    from app.models.engagement import Engagement
    from app.models.run import Run

OPENGREP_BIN = "opengrep"


class OpengrepRunner(StrixRunner):
    """Opengrep engine — repo SAST behind the authorization gate."""

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
        src_root = run_dir / "src"
        src_root.mkdir(parents=True, exist_ok=True)

        scope_note = run_dir / "scope.txt"
        try:
            scope_note.write_text(
                "Authorized Opengrep scan. Repos are gate-cleared:\n"
                + "\n".join(f"- {t}" for t in (run.targets or [])),
                encoding="utf-8",
            )
        except OSError:  # pragma: no cover
            pass

        command = _build_opengrep_command(run.targets or [], run_dir, src_root)
        verify_model = resolve_model_profile(getattr(run, "model_profile", None)).verify
        return StrixInvocation(
            run_dir=run_dir,
            instruction_path=scope_note,
            model="opengrep",
            verify_model=verify_model,
            profile_name="opengrep",
            env=dict(os.environ),
            command=command,
            log_path=run_dir / "opengrep.stdout.log",
            pid_path=run_dir / "opengrep.pid",
        )

    def _build_result(
        self,
        invocation: StrixInvocation,
        *,
        returncode: int | None,
        error: str | None,
        stopped: bool,
    ) -> StrixRunResult:
        reports = sorted(invocation.run_dir.glob("opengrep.*.json"))
        parser = get_parser("opengrep")
        findings: list[ParsedVulnerability] = []
        for report in reports:
            try:
                text = report.read_text(encoding="utf-8")
            except OSError:
                continue
            if parser is not None:
                for finding in parser.parse(text):
                    evidence = dict(finding.evidence or {})
                    if "check_id" in evidence and "rule" not in evidence:
                        evidence["rule"] = evidence.get("check_id")
                    evidence["confidence"] = "medium"
                    finding.evidence = evidence
                    findings.append(finding)
        report_present = any(r.exists() for r in reports)
        return StrixRunResult(
            returncode=returncode,
            findings=findings,
            metadata={
                "engine": "opengrep",
                "returncode": returncode,
                "finding_count": len(findings),
                "report_present": report_present,
            },
            report_path=None,
            error=error,
            stopped=stopped,
        )

    def _engine_completed(self, result: StrixRunResult) -> bool:
        return result.returncode == 0 or bool(result.metadata.get("report_present"))


def _build_opengrep_command(targets: list[str], run_dir: Path, src_root: Path) -> list[str]:
    lines = ["set +e"]
    for i, target in enumerate(targets):
        src_dir = src_root / f"repo{i}"
        report = run_dir / f"opengrep.{i}.json"
        tq = shlex.quote(str(target))
        sq = shlex.quote(str(src_dir))
        rq = shlex.quote(str(report))
        lines.append(
            f'if [ -d {tq} ]; then SRC={tq}; '
            f'else mkdir -p {sq} && git clone {tq} {sq} && SRC={sq}; fi; '
            f'{OPENGREP_BIN} scan --json -o {rq} --config auto "$SRC" || true'
        )
    return ["bash", "-c", "\n".join(lines)]
