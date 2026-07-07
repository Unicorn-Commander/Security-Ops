"""app.engine.gitleaks_runner — the Gitleaks engine (engine #3, secret scanning, MIT).

Scans a git repository for hard-coded secrets (API keys, tokens, private keys) in
the working tree AND commit history, behind the **same** authorization gate +
attestation + findings/verify pipeline as Strix and Nuclei. Gitleaks rides the
existing :class:`~app.models.target.TargetKind.REPO` target kind — a run only needs
``engine="gitleaks"`` and one or more repo targets (git URL or local path).

:class:`GitleaksRunner` subclasses :class:`~app.engine.strix_runner.StrixRunner` to
reuse the entire gate-cleared execute pipeline (emergency-stop re-check → RUNNING →
spawn+wait with cross-container E-stop → store findings → verify pass → terminal
status). It overrides ONLY the three engine seams:

* :meth:`prepare` — clone/reference each repo into the run dir, then build the
  ``gitleaks detect`` command (no LLM env needed).
* :meth:`_build_result` — parse gitleaks' JSON report(s) into normalized findings.
* :meth:`_engine_completed` — gitleaks exits 0 on a clean run; with ``--exit-code 0``
  it also exits 0 when leaks are found, so a produced report == success (mirrors
  Nuclei's non-zero-on-match tolerance).

SECURITY — never persist a plaintext secret. Gitleaks writes the raw ``Secret`` /
``Match`` into its transient on-disk report (on the isolated, ephemeral runner), but
this parser copies ONLY the rule, file, line, commit metadata, and a *redacted
fingerprint* (first 4 chars + length) into the Finding. The raw secret never reaches
a Finding field, ``payload``, ``poc``, ``evidence``, or ``raw``. This platform must
never become a secret-exfil vector. See :func:`_redact_secret` /
:func:`_sanitize_gitleaks_item` and the redaction assertion in
``tests/test_gitleaks_parse.py``.

(DefectDojo's BSD-3 parser corpus is the long-term normalizer strategy for the
multi-engine roadmap; at two new engines a direct parser matching the Nuclei
pattern is the right call — no Django-based lib to vendor.)
"""

from __future__ import annotations

import json
import logging
import os
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.engine.strix_runner import (
    ParsedVulnerability,
    StrixInvocation,
    StrixRunResult,
    StrixRunner,
    _first,
    _to_str,
    resolve_model_profile,
)
from app.models.finding import FindingSeverity

if TYPE_CHECKING:  # pragma: no cover
    from app.models.engagement import Engagement
    from app.models.run import Run

log = logging.getLogger("secops.engine.gitleaks")

GITLEAKS_BIN = "gitleaks"

#: Secrets are HIGH severity by default (a leaked credential is directly actionable).
_SECRET_SEVERITY = FindingSeverity.HIGH
#: Hard-coded credentials.
_SECRET_CWE = "CWE-798"


class GitleaksRunner(StrixRunner):
    """Gitleaks engine — repo secret scanning behind the authorization gate."""

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

        # Belt-and-suspenders scope note (advisory; the GATE is the authority).
        scope_note = run_dir / "scope.txt"
        try:
            scope_note.write_text(
                "Authorized Gitleaks scan. Repos are gate-cleared:\n"
                + "\n".join(f"- {t}" for t in (run.targets or [])),
                encoding="utf-8",
            )
        except OSError:  # pragma: no cover
            pass

        # Build a single shell command that materializes each repo (clone URLs,
        # reference existing local paths) and runs gitleaks against it, writing one
        # JSON report per target. Doing the clone INSIDE the spawned process (not in
        # this sync method) keeps it interruptible by the cross-container E-stop and
        # off the event loop; ``|| true`` per target keeps one bad repo from aborting
        # the rest (the parser tolerates missing/blank reports).
        command = _build_gitleaks_command(run.targets or [], run_dir, src_root)

        # The verify pass uses the profile's verify model; the "sweep" label is the
        # engine name (gitleaks), so verify runs (label != verify model).
        verify_model = resolve_model_profile(getattr(run, "model_profile", None)).verify
        return StrixInvocation(
            run_dir=run_dir,
            instruction_path=scope_note,
            model="gitleaks",
            verify_model=verify_model,
            profile_name="gitleaks",
            env=dict(os.environ),
            command=command,
            log_path=run_dir / "gitleaks.stdout.log",
            pid_path=run_dir / "gitleaks.pid",
        )

    def _build_result(
        self,
        invocation: StrixInvocation,
        *,
        returncode: int | None,
        error: str | None,
        stopped: bool,
    ) -> StrixRunResult:
        reports = sorted(invocation.run_dir.glob("gitleaks.*.json"))
        findings: list[ParsedVulnerability] = []
        for report in reports:
            findings.extend(_parse_gitleaks_json(report))
        report_present = any(r.exists() for r in reports)
        return StrixRunResult(
            returncode=returncode,
            findings=findings,
            metadata={
                "engine": "gitleaks",
                "returncode": returncode,
                "finding_count": len(findings),
                "report_present": report_present,
            },
            report_path=None,
            error=error,
            stopped=stopped,
        )

    def _engine_completed(self, result: StrixRunResult) -> bool:
        """Gitleaks exits 0 on a clean run; with ``--exit-code 0`` it exits 0 even
        when leaks are found. A produced report means the scan ran, so treat that as
        success regardless of the (loop's) exit code — mirroring Nuclei's tolerance
        for its non-zero-on-match convention."""
        return result.returncode == 0 or bool(result.metadata.get("report_present"))


# ---------------------------------------------------------------------------
# Command building (near-pure) — clone/reference each repo, run gitleaks per target
# ---------------------------------------------------------------------------
def _build_gitleaks_command(
    targets: list[str], run_dir: Path, src_root: Path
) -> list[str]:
    """Build the ``bash -c`` command that materializes + scans every repo target.

    For each target: if it is an existing local directory use it as the source; else
    ``git clone`` it into ``<run_dir>/src/repo<i>``. Then run
    ``gitleaks detect --source <src> --report-format json --report-path
    <run_dir>/gitleaks.<i>.json --no-banner --exit-code 0``. ``--exit-code 0`` keeps a
    leak from looking like a crash; ``|| true`` isolates per-repo failures.
    """
    lines = ["set +e"]
    for i, target in enumerate(targets):
        src_dir = src_root / f"repo{i}"
        report = run_dir / f"gitleaks.{i}.json"
        tq = shlex.quote(str(target))
        sq = shlex.quote(str(src_dir))
        rq = shlex.quote(str(report))
        lines.append(
            f'if [ -d {tq} ]; then SRC={tq}; '
            f'else mkdir -p {sq} && git clone {tq} {sq} && SRC={sq}; fi; '
            f'{GITLEAKS_BIN} detect --source "$SRC" --report-format json '
            f"--report-path {rq} --no-banner --exit-code 0 --log-level error || true"
        )
    return ["bash", "-c", "\n".join(lines)]


# ---------------------------------------------------------------------------
# Gitleaks JSON parsing (pure) — one finding per report entry
# ---------------------------------------------------------------------------
def _parse_gitleaks_json(path: Path | str) -> list[ParsedVulnerability]:
    """Parse a gitleaks JSON report (a top-level array of leak objects) into
    normalized findings. Tolerant of a missing file, blank content (gitleaks writes
    ``[]`` or nothing on a clean repo), and malformed JSON (skipped, logged)."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        text = p.read_text(encoding="utf-8").strip()
    except OSError as exc:  # pragma: no cover
        log.warning("gitleaks.parse read failed for %s: %s", p, exc)
        return []
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        log.warning("gitleaks.parse: skipping malformed report %s", p)
        return []
    if not isinstance(data, list):
        # Defensive: some gitleaks versions can emit an object wrapper.
        data = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(data, list):
            return []
    return [_vuln_from_gitleaks(item) for item in data if isinstance(item, dict)]


def _redact_secret(value: Any) -> str | None:
    """Redact a plaintext secret to a non-reversible fingerprint: first 4 chars +
    length (e.g. ``AKIA…(len=40)``). NEVER returns the full secret. Returns ``None``
    for an empty value so no fingerprint field is stored when there is nothing to
    redact."""
    if not value:
        return None
    s = str(value)
    prefix = s[:4]
    return f"{prefix}…(len={len(s)})"


#: Fields that carry the plaintext secret — dropped before anything is retained.
_SECRET_FIELDS = ("Secret", "secret", "Match", "match")


def _sanitize_gitleaks_item(item: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a gitleaks leak object with the plaintext secret fields
    (``Secret`` / ``Match``) removed, so it is safe to retain as evidence/raw."""
    return {k: v for k, v in item.items() if k not in _SECRET_FIELDS}


def _vuln_from_gitleaks(item: dict[str, Any]) -> ParsedVulnerability:
    rule_id = _to_str(_first(item, "RuleID", "ruleID", "rule_id"))
    title = _to_str(_first(item, "Description", "description")) or rule_id or "Secret detected"
    file = _to_str(_first(item, "File", "file"))
    start_line = _first(item, "StartLine", "startLine", "start_line")
    endpoint = f"{file}:{start_line}" if file and start_line is not None else file
    # gitleaks' own "Fingerprint" is a LOCATION id (``file:rule:line``) — NOT the
    # secret, so it is safe to keep and use for de-dup / PoC reference.
    gl_fingerprint = _to_str(_first(item, "Fingerprint", "fingerprint"))
    # Redact the plaintext to a non-reversible fingerprint; the raw secret is dropped.
    secret_fingerprint = _redact_secret(_first(item, "Secret", "secret", default=None))

    evidence: dict[str, Any] = {
        "engine": "gitleaks",
        "rule_id": rule_id,
        "file": file,
        "line": start_line,
        "commit": _to_str(_first(item, "Commit", "commit")),
        "author": _to_str(_first(item, "Author", "author")),
        "email": _to_str(_first(item, "Email", "email")),
        "date": _to_str(_first(item, "Date", "date")),
        "tags": item.get("Tags") or item.get("tags"),
        "gitleaks_fingerprint": gl_fingerprint,
        # Redacted fingerprint of the secret — NEVER the plaintext.
        "secret_fingerprint": secret_fingerprint,
        # Sanitized copy (plaintext Secret/Match stripped) for downstream context.
        "raw": _sanitize_gitleaks_item(item),
    }
    return ParsedVulnerability(
        title=str(title),
        severity=_SECRET_SEVERITY,
        cwe=_SECRET_CWE,
        endpoint=endpoint,
        payload=None,  # NEVER the raw match/secret.
        poc=gl_fingerprint,  # location id, not the secret.
        evidence={k: v for k, v in evidence.items() if v is not None or k == "raw"},
        raw=_sanitize_gitleaks_item(item),
    )
