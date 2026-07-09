"""app.engine.zap_runner — OWASP ZAP baseline engine (DAST).

Runs the baseline scan one target at a time, stores the JSON report per target, and
normalizes it through the shared parser registry.
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

ZAP_BASELINE = "zap-baseline.py"


class ZapRunner(StrixRunner):
    """ZAP engine — baseline DAST behind the authorization gate."""

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
                "Authorized ZAP scan. Targets are gate-cleared:\n"
                + "\n".join(f"- {t}" for t in (run.targets or [])),
                encoding="utf-8",
            )
        except OSError:  # pragma: no cover
            pass

        command = _build_zap_command(run.targets or [], run_dir)
        verify_model = resolve_model_profile(getattr(run, "model_profile", None)).verify
        return StrixInvocation(
            run_dir=run_dir,
            instruction_path=scope_note,
            model="zap",
            verify_model=verify_model,
            profile_name="zap",
            env=dict(os.environ),
            command=command,
            log_path=run_dir / "zap.stdout.log",
            pid_path=run_dir / "zap.pid",
        )

    def _build_result(
        self,
        invocation: StrixInvocation,
        *,
        returncode: int | None,
        error: str | None,
        stopped: bool,
    ) -> StrixRunResult:
        reports = sorted(invocation.run_dir.glob("zap.*.json"))
        parser = get_parser("zap")
        findings: list[ParsedVulnerability] = []
        for report in reports:
            try:
                text = report.read_text(encoding="utf-8")
            except OSError:
                continue
            if parser is not None:
                for finding in parser.parse(text):
                    evidence = dict(finding.evidence or {})
                    evidence["confidence"] = "medium"
                    finding.evidence = evidence
                    findings.append(finding)
        report_present = any(r.exists() for r in reports)
        return StrixRunResult(
            returncode=returncode,
            findings=findings,
            metadata={
                "engine": "zap",
                "returncode": returncode,
                "finding_count": len(findings),
                "report_present": report_present,
            },
            report_path=None,
            error=error,
            stopped=stopped,
        )

    def _engine_completed(self, result: StrixRunResult) -> bool:
        return result.returncode in (0, 1, 2) or bool(result.metadata.get("report_present"))


def _build_zap_command(targets: list[str], run_dir: Path) -> list[str]:
    lines = ["set +e"]
    for i, target in enumerate(targets):
        report = run_dir / f"zap.{i}.json"
        tq = shlex.quote(str(target))
        rq = shlex.quote(str(report))
        # TODO multi-target: baseline runs one target per invocation by design here.
        lines.append(f"{ZAP_BASELINE} -t {tq} -J {rq} -I || true")
    return ["bash", "-c", "\n".join(lines)]
