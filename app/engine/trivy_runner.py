"""app.engine.trivy_runner — the Trivy engine (engine #4, CVE/SCA/IaC/secret, Apache-2.0).

Scans a container image (``trivy image``) or a repository/filesystem (``trivy fs`` /
``trivy repo``) for known-vulnerable packages (CVEs), misconfigurations (IaC), and
hard-coded secrets, behind the **same** authorization gate + attestation +
findings/verify pipeline as Strix, Nuclei, and Gitleaks. Trivy adds a NEW target
kind — :class:`~app.models.target.TargetKind.IMAGE` (a container image ref) — and
also rides the existing ``REPO`` kind.

:class:`TrivyRunner` subclasses :class:`~app.engine.strix_runner.StrixRunner` to
reuse the entire gate-cleared execute pipeline. It overrides ONLY the three engine
seams:

* :meth:`prepare` — pick the trivy subcommand per target (``image`` / ``fs`` /
  ``repo``) and build the command (no LLM env needed).
* :meth:`_build_result` — parse trivy's JSON report(s) into normalized findings
  (vulnerabilities, misconfigurations, and secrets).
* :meth:`_engine_completed` — trivy exits 0 on a successful scan (findings do NOT
  change the exit code unless ``--exit-code`` is set, which we do not), so a produced
  report == success.

SECURITY — never persist a plaintext secret. Trivy's ``Secrets`` results carry the
raw ``Match`` / ``Code`` on the transient runner-side report; this parser copies ONLY
the rule, category, line, and a *redacted fingerprint* into the Finding — never the
plaintext (same rule as Gitleaks). See :func:`_sanitize_trivy_secret`.

(DefectDojo's BSD-3 Trivy parser is the long-term normalizer strategy for the
multi-engine roadmap; at two new engines a direct parser matching the Nuclei pattern
is the right call — no Django-based lib to vendor.)
"""

from __future__ import annotations

import json
import logging
import os
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.engine.gitleaks_runner import _redact_secret
from app.engine.enrich import enrich_cves
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
from app.models.finding import FindingSeverity

if TYPE_CHECKING:  # pragma: no cover
    from app.models.engagement import Engagement
    from app.models.run import Run

log = logging.getLogger("secops.engine.trivy")

TRIVY_BIN = "trivy"

#: A secret found by trivy is HIGH by default (trivy usually rates them CRITICAL/HIGH
#: itself; this is the floor when trivy gives no severity).
_SECRET_SEVERITY = FindingSeverity.HIGH
_SECRET_CWE = "CWE-798"

#: Scanners enabled for every trivy run: package CVEs, IaC misconfig, secrets.
_SCANNERS = "vuln,secret,misconfig"


class TrivyRunner(StrixRunner):
    """Trivy engine — image/repo CVE + misconfig + secret scanning behind the gate."""

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

        # Belt-and-suspenders scope note (advisory; the GATE is the authority).
        scope_note = run_dir / "scope.txt"
        try:
            scope_note.write_text(
                "Authorized Trivy scan. Targets are gate-cleared:\n"
                + "\n".join(f"- {t}" for t in (run.targets or [])),
                encoding="utf-8",
            )
        except OSError:  # pragma: no cover
            pass

        command = _build_trivy_command(run.targets or [], run_dir)

        verify_model = resolve_model_profile(getattr(run, "model_profile", None)).verify
        return StrixInvocation(
            run_dir=run_dir,
            instruction_path=scope_note,
            model="trivy",
            verify_model=verify_model,
            profile_name="trivy",
            env=dict(os.environ),
            command=command,
            log_path=run_dir / "trivy.stdout.log",
            pid_path=run_dir / "trivy.pid",
        )

    async def _build_result(
        self,
        invocation: StrixInvocation,
        *,
        returncode: int | None,
        error: str | None,
        stopped: bool,
    ) -> StrixRunResult:
        reports = sorted(invocation.run_dir.glob("trivy.*.json"))
        findings: list[ParsedVulnerability] = []
        for report in reports:
            findings.extend(_parse_trivy_json(report))
        if findings and getattr(self.settings, "enrichment_enabled", True):
            await enrich_cves(findings)
        report_present = any(r.exists() for r in reports)
        return StrixRunResult(
            returncode=returncode,
            findings=findings,
            metadata={
                "engine": "trivy",
                "returncode": returncode,
                "finding_count": len(findings),
                "report_present": report_present,
            },
            report_path=None,
            error=error,
            stopped=stopped,
        )

    def _engine_completed(self, result: StrixRunResult) -> bool:
        """Trivy exits 0 on a successful scan (findings alone do not change the exit
        code — we do not set ``--exit-code``). A produced report means the scan ran,
        so treat that as success even if the (loop's) exit code is non-zero."""
        return result.returncode == 0 or bool(result.metadata.get("report_present"))


# ---------------------------------------------------------------------------
# Command building (near-pure) — pick the subcommand per target, run trivy per target
# ---------------------------------------------------------------------------
def _trivy_target_mode(target: str) -> str:
    """Classify a target string into a trivy subcommand.

    * an existing local directory → ``fs`` (scan the filesystem tree),
    * a git remote (``git@…`` / ``…://…`` / ``….git``) → ``repo`` (trivy clones+scans),
    * anything else → ``image`` (a container image reference).

    This is a heuristic because a :class:`~app.models.run.Run` stores targets as bare
    strings (not their :class:`~app.models.target.TargetKind`); it is deliberately
    conservative — image refs have no ``://`` and are not on disk.
    """
    t = (target or "").strip()
    if os.path.isdir(t):
        return "fs"
    if t.startswith("git@") or "://" in t or t.endswith(".git"):
        return "repo"
    return "image"


def _build_trivy_command(targets: list[str], run_dir: Path) -> list[str]:
    """Build the ``bash -c`` command that scans every target with trivy, one JSON
    report per target (``trivy.<i>.json``). Each invocation enables the vuln, secret,
    and misconfig scanners. ``|| true`` isolates a per-target failure; the parser
    tolerates missing/blank reports."""
    lines = ["set +e"]
    for i, target in enumerate(targets):
        mode = _trivy_target_mode(target)
        report = run_dir / f"trivy.{i}.json"
        tq = shlex.quote(str(target))
        rq = shlex.quote(str(report))
        lines.append(
            f"{TRIVY_BIN} {mode} --format json --output {rq} "
            f"--scanners {_SCANNERS} {tq} || true"
        )
    return ["bash", "-c", "\n".join(lines)]


# ---------------------------------------------------------------------------
# Trivy JSON parsing (pure) — Results[] → {Vulnerabilities,Misconfigurations,Secrets}
# ---------------------------------------------------------------------------
def _parse_trivy_json(path: Path | str) -> list[ParsedVulnerability]:
    """Parse a trivy JSON report into normalized findings. Tolerant of a missing
    file, blank content, malformed JSON, and a missing ``Results`` block."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        text = p.read_text(encoding="utf-8").strip()
    except OSError as exc:  # pragma: no cover
        log.warning("trivy.parse read failed for %s: %s", p, exc)
        return []
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        log.warning("trivy.parse: skipping malformed report %s", p)
        return []
    if not isinstance(data, dict):
        return []
    results = data.get("Results")
    if not isinstance(results, list):
        return []

    out: list[ParsedVulnerability] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = _to_str(_first(result, "Target", "target"))
        for vuln in result.get("Vulnerabilities") or []:
            if isinstance(vuln, dict):
                out.append(_vuln_from_trivy_vuln(vuln, target))
        for misconf in result.get("Misconfigurations") or []:
            if isinstance(misconf, dict):
                out.append(_finding_from_trivy_misconfig(misconf, target))
        for secret in result.get("Secrets") or []:
            if isinstance(secret, dict):
                out.append(_finding_from_trivy_secret(secret, target))
    return out


def _cwe_first(value: Any) -> Any:
    """Trivy ``CweIDs`` is a list (``["CWE-125"]``)."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _vuln_from_trivy_vuln(item: dict[str, Any], target: str | None) -> ParsedVulnerability:
    vuln_id = _to_str(_first(item, "VulnerabilityID", "vulnerabilityID", "id"))
    name = _to_str(_first(item, "Title", "title"))
    title = f"{vuln_id}: {name}" if vuln_id and name else (name or vuln_id or "Vulnerability")
    pkg = _to_str(_first(item, "PkgName", "pkgName"))
    installed = _to_str(_first(item, "InstalledVersion", "installedVersion"))
    fixed = _to_str(_first(item, "FixedVersion", "fixedVersion"))
    endpoint = f"{pkg}@{installed}" if pkg and installed else pkg
    cwe = _normalize_cwe(_cwe_first(item.get("CweIDs") or item.get("cweIDs")))
    payload = f"Upgrade {pkg} to {fixed}" if pkg and fixed else (f"Fixed in {fixed}" if fixed else None)

    evidence: dict[str, Any] = {
        "engine": "trivy",
        "type": "vulnerability",
        "vuln_id": vuln_id,
        "pkg": pkg,
        "installed": installed,
        "fixed": fixed,
        "target": target,
        "description": _to_str(_first(item, "Description", "description")),
        "references": item.get("References") or item.get("references"),
        "primary_url": _to_str(_first(item, "PrimaryURL", "primaryURL")),
        "raw": item,
    }
    return ParsedVulnerability(
        title=str(title),
        severity=map_severity(_first(item, "Severity", "severity")),
        cwe=cwe,
        endpoint=endpoint,
        payload=payload,
        poc=_to_str(_first(item, "PrimaryURL", "primaryURL")),
        evidence={k: v for k, v in evidence.items() if v is not None or k == "raw"},
        raw=item,
    )


def _finding_from_trivy_misconfig(item: dict[str, Any], target: str | None) -> ParsedVulnerability:
    misconf_id = _to_str(_first(item, "ID", "id", "AVDID", "avdID"))
    name = _to_str(_first(item, "Title", "title"))
    title = f"{misconf_id}: {name}" if misconf_id and name else (name or misconf_id or "Misconfiguration")
    resolution = _to_str(_first(item, "Resolution", "resolution"))

    evidence: dict[str, Any] = {
        "engine": "trivy",
        "type": "misconfig",
        "misconf_id": misconf_id,
        "target": target,
        "message": _to_str(_first(item, "Message", "message")),
        "description": _to_str(_first(item, "Description", "description")),
        "resolution": resolution,
        "references": item.get("References") or item.get("references"),
        "raw": item,
    }
    return ParsedVulnerability(
        title=str(title),
        severity=map_severity(_first(item, "Severity", "severity")),
        cwe=None,  # trivy misconfigs are keyed by AVD ids, not CWE.
        endpoint=target,
        payload=resolution,
        poc=_to_str(_first(item, "PrimaryURL", "primaryURL")),
        evidence={k: v for k, v in evidence.items() if v is not None or k == "raw"},
        raw=item,
    )


#: Fields on a trivy Secret result that carry the plaintext leak.
_SECRET_FIELDS = ("Match", "match", "Code", "code")


def _sanitize_trivy_secret(item: dict[str, Any]) -> dict[str, Any]:
    """Copy of a trivy Secret result with the plaintext-bearing fields (``Match`` /
    ``Code``) removed, so it is safe to retain as evidence/raw."""
    return {k: v for k, v in item.items() if k not in _SECRET_FIELDS}


def _finding_from_trivy_secret(item: dict[str, Any], target: str | None) -> ParsedVulnerability:
    rule_id = _to_str(_first(item, "RuleID", "ruleID", "rule_id"))
    category = _to_str(_first(item, "Category", "category"))
    name = _to_str(_first(item, "Title", "title"))
    title = f"{rule_id}: {name}" if rule_id and name else (name or category or rule_id or "Secret detected")
    start_line = _first(item, "StartLine", "startLine", "start_line")
    endpoint = f"{target}:{start_line}" if target and start_line is not None else target
    raw_severity = _first(item, "Severity", "severity")
    severity = map_severity(raw_severity) if raw_severity else _SECRET_SEVERITY
    # Redact the plaintext match to a non-reversible fingerprint; drop the raw match.
    secret_fingerprint = _redact_secret(_first(item, "Match", "match", default=None))

    evidence: dict[str, Any] = {
        "engine": "trivy",
        "type": "secret",
        "rule_id": rule_id,
        "category": category,
        "line": start_line,
        "target": target,
        "severity_raw": _to_str(raw_severity),
        # Redacted fingerprint — NEVER the plaintext match/code.
        "secret_fingerprint": secret_fingerprint,
        "raw": _sanitize_trivy_secret(item),
    }
    return ParsedVulnerability(
        title=str(title),
        severity=severity,
        cwe=_SECRET_CWE,
        endpoint=endpoint,
        payload=None,  # NEVER the raw match/code.
        poc=None,
        evidence={k: v for k, v in evidence.items() if v is not None or k == "raw"},
        raw=_sanitize_trivy_secret(item),
    )
