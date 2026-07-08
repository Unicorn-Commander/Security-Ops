"""app.engine.nuclei_runner — the Nuclei engine (ProjectDiscovery, MIT).

Templated breadth scanning (10k+ community checks) alongside Strix's autonomous
depth, behind the **same** authorization gate + attestation + findings/verify
pipeline. Nuclei rides the existing web ``target`` + attestation model — no new
target kind — so a run only needs ``engine="nuclei"``.

:class:`NucleiRunner` subclasses :class:`~app.engine.strix_runner.StrixRunner` to
reuse the entire gate-cleared execute pipeline (emergency-stop re-check → RUNNING →
spawn+wait with cross-container E-stop → store findings → verify pass → terminal
status). It overrides ONLY the three engine seams:

* :meth:`prepare` — build the ``nuclei`` command + run dir (no LLM env needed).
* :meth:`_build_result` — parse Nuclei's JSONL into normalized findings.
* :meth:`_engine_completed` — Nuclei signals success with a zero exit code (unlike
  Strix, which exits non-zero when it finds vulns and reports status in run.json).

The verify pass still applies: each Nuclei finding is re-checked by the model
profile's verify model (``nuclei`` sweep label != the verify model), so templated
hits get an LLM second opinion just like Strix findings.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.engine.strix_runner import (
    ParsedVulnerability,
    StrixInvocation,
    StrixRunResult,
    StrixRunner,
    _first,
    _normalize_cwe,
    _to_str,
    map_severity,
    resolve_model_profile,
)
from app.models.run import RunMode

if TYPE_CHECKING:  # pragma: no cover
    from app.models.engagement import Engagement
    from app.models.run import Run

log = logging.getLogger("secops.engine.nuclei")

NUCLEI_BIN = "nuclei"

# Per-mode tuning: QUICK = high-signal severities + brisk rate; DEEP = everything.
_MODE_ARGS: dict[RunMode, list[str]] = {
    RunMode.QUICK: ["-severity", "critical,high,medium", "-rate-limit", "150"],
    RunMode.STANDARD: ["-severity", "critical,high,medium,low", "-rate-limit", "150"],
    RunMode.DEEP: ["-rate-limit", "100"],  # all severities, gentler rate
}


class NucleiRunner(StrixRunner):
    """Nuclei engine — templated breadth scanning behind the authorization gate."""

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
        out_path = run_dir / "nuclei.jsonl"
        # Belt-and-suspenders scope note (advisory; the GATE is the authority).
        scope_note = run_dir / "scope.txt"
        try:
            scope_note.write_text(
                "Authorized Nuclei scan. Targets are gate-cleared:\n"
                + "\n".join(f"- {t}" for t in (run.targets or [])),
                encoding="utf-8",
            )
        except OSError:  # pragma: no cover
            pass

        cmd: list[str] = [
            NUCLEI_BIN,
            "-jsonl",
            "-output",
            str(out_path),
            "-no-color",
            "-disable-update-check",
            "-stats",
        ]
        for target in run.targets or []:
            cmd += ["-target", str(target)]
        cmd += _MODE_ARGS.get(run.mode, _MODE_ARGS[RunMode.STANDARD])

        # The verify pass uses the profile's verify model; the "sweep" label is the
        # engine name (nuclei), so verify runs (label != verify model).
        verify_model = resolve_model_profile(getattr(run, "model_profile", None)).verify
        return StrixInvocation(
            run_dir=run_dir,
            instruction_path=scope_note,
            model="nuclei",
            verify_model=verify_model,
            profile_name="nuclei",
            env=dict(os.environ),
            command=cmd,
            log_path=run_dir / "nuclei.stdout.log",
            pid_path=run_dir / "nuclei.pid",
        )

    def _build_result(
        self,
        invocation: StrixInvocation,
        *,
        returncode: int | None,
        error: str | None,
        stopped: bool,
    ) -> StrixRunResult:
        findings = _parse_nuclei_jsonl(invocation.run_dir / "nuclei.jsonl")
        return StrixRunResult(
            returncode=returncode,
            findings=findings,
            metadata={"engine": "nuclei", "returncode": returncode, "finding_count": len(findings)},
            report_path=None,
            error=error,
            stopped=stopped,
        )

    def _engine_completed(self, result: StrixRunResult) -> bool:
        """Nuclei exits 0 on a clean run (with or without findings); a non-zero exit
        means the scan errored. (Strix inverts this — hence the per-engine seam.)"""
        return result.returncode == 0


# ---------------------------------------------------------------------------
# Nuclei JSONL parsing (pure) — one finding per line
# ---------------------------------------------------------------------------
def _parse_nuclei_jsonl(path: Path | str) -> list[ParsedVulnerability]:
    """Parse Nuclei ``-jsonl`` output (one JSON object per line) into normalized
    findings. Tolerant of blank lines and malformed rows (skipped, logged)."""
    p = Path(path)
    if not p.exists():
        return []
    out: list[ParsedVulnerability] = []
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover
        log.warning("nuclei.parse read failed for %s: %s", p, exc)
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            log.warning("nuclei.parse: skipping malformed jsonl line")
            continue
        if isinstance(item, dict):
            out.append(_vuln_from_nuclei(item))
    return out


def _vuln_from_nuclei(item: dict[str, Any]) -> ParsedVulnerability:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    template_id = _first(item, "template-id", "templateID", "template")
    title = _to_str(_first(info, "name", default=None)) or (str(template_id) if template_id else "Nuclei finding")
    endpoint = _to_str(_first(item, "matched-at", "matched_at", "host", "url"))
    cwe = _normalize_cwe(_cwe_first(classification.get("cwe-id") or classification.get("cwe_id")))
    references = info.get("reference") or info.get("references")
    evidence: dict[str, Any] = {
        "raw": item,
        "engine": "nuclei",
        "template_id": str(template_id) if template_id else None,
        "description": _to_str(info.get("description")),
        "tags": info.get("tags"),
        "references": references,
        "cve": _cwe_first(classification.get("cve-id") or classification.get("cve_id")),
        "extracted": item.get("extracted-results") or item.get("extracted_results"),
    }
    return ParsedVulnerability(
        title=str(title),
        severity=map_severity(info.get("severity")),
        cwe=cwe,
        endpoint=endpoint,
        payload=_to_str(_first(item, "curl-command", "curl_command", "request")),
        poc=_to_str(_first(item, "matched-at", "matched_at")),
        evidence={k: v for k, v in evidence.items() if v is not None or k == "raw"},
        raw=item,
    )


def _cwe_first(value: Any) -> Any:
    """Nuclei classification ids are usually lists (``["CWE-89"]``)."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value
