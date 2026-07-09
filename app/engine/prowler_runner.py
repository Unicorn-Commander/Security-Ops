"""app.engine.prowler_runner — the Prowler engine (Apache-2.0, CSPM cloud posture).

Cloud Security Posture Management: scans a CLOUD_ACCOUNT target (``aws:<id>`` /
``gcp:<project>`` / ``azure:<subscription>``) for hundreds of misconfiguration checks
across the account, behind the **same** authorization gate + attestation + findings /
verify pipeline as every other engine. Prowler introduces the ``CLOUD_ACCOUNT`` target
kind, authorized by the ``CLOUD_ROLE`` possession proof (assume a scoped role granted
with our per-target external ID — see ``app/authz/cloud_proof.py``), so a run only needs
``engine="prowler"`` over an attested cloud target.

:class:`ProwlerRunner` subclasses :class:`~app.engine.strix_runner.StrixRunner` to reuse
the entire gate-cleared execute pipeline (emergency-stop re-check → RUNNING → spawn+wait
with cross-container E-stop → store findings → verify pass → terminal status). It
overrides ONLY the three engine seams:

* :meth:`prepare` — build the ``prowler <provider>`` command + run dir (no LLM env).
* :meth:`_build_result` — parse Prowler's OCSF JSON into normalized findings (FAILs only;
  PASS/MANUAL checks are compliant/non-findings).
* :meth:`_engine_completed` — Prowler exits ``0`` when all checks pass and ``3`` when it
  found failing checks (both are a successful *run*); any other code is an error.

Runtime cloud credentials are a DEPLOY concern, exactly like Strix's sandbox image and
the model gateway key: the ``secops-runner`` re-assumes the attested role (the role ARN +
our external ID are recorded on the target's ``attestation_evidence`` by the CLOUD_ROLE
proof) and exposes creds to the subprocess. The GATE — not the runner — is the
authorization boundary; by the time :meth:`prepare` runs, every target has already
cleared ``enforce_scope`` (attested CLOUD_ROLE + in-scope + ACTIVE engagement).
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
    _to_str,
    map_severity,
    resolve_model_profile,
)
from app.models.run import RunMode

if TYPE_CHECKING:  # pragma: no cover
    from app.models.engagement import Engagement
    from app.models.run import Run

log = logging.getLogger("secops.engine.prowler")

PROWLER_BIN = "prowler"

# Prowler exits 3 (not 0) when it found failing checks — a successful scan that has
# findings, analogous to Strix's non-zero-on-vulns convention (hence the seam).
_PROWLER_FINDINGS_EXIT = 3

# Map a CLOUD_ACCOUNT value's provider to the Prowler provider subcommand.
_PROVIDER_SUBCOMMAND = {"aws": "aws", "gcp": "gcp", "azure": "azure"}


def _provider_account(target: str) -> tuple[str, str]:
    """Split ``<provider>:<account>`` → ``(provider, account)`` (provider lower-cased);
    defaults to ``("aws", <target>)`` for a bare value so a mis-shaped target still runs
    an AWS scan rather than crashing the seam."""
    raw = str(target or "").strip()
    if ":" in raw:
        provider, _, account = raw.partition(":")
        provider = provider.strip().lower()
        if provider in _PROVIDER_SUBCOMMAND:
            return provider, account.strip()
    return "aws", raw


class ProwlerRunner(StrixRunner):
    """Prowler engine — cloud-account posture (CSPM) behind the authorization gate."""

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

        # Prowler is single-provider per invocation; the first gate-cleared target sets
        # the provider (a run is a homogeneous set of cloud accounts of one provider).
        targets = list(run.targets or [])
        provider, _account = _provider_account(targets[0]) if targets else ("aws", "")
        subcommand = _PROVIDER_SUBCOMMAND.get(provider, "aws")

        scope_note = run_dir / "scope.txt"
        try:
            scope_note.write_text(
                "Authorized Prowler CSPM scan. Cloud accounts are gate-cleared "
                "(CLOUD_ROLE-attested):\n" + "\n".join(f"- {t}" for t in targets),
                encoding="utf-8",
            )
        except OSError:  # pragma: no cover
            pass

        cmd: list[str] = [
            PROWLER_BIN,
            subcommand,
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            str(run_dir),
            "--output-filename",
            "prowler",
            "--status",
            "FAIL",  # only failing checks become findings; PASS = compliant
            "--no-banner",
        ]
        # DEEP scans keep manual/muted checks too; QUICK/STANDARD stay FAIL-only above.
        if run.mode == RunMode.DEEP:
            cmd += ["--verbose"]

        verify_model = resolve_model_profile(getattr(run, "model_profile", None)).verify
        return StrixInvocation(
            run_dir=run_dir,
            instruction_path=scope_note,
            model="prowler",
            verify_model=verify_model,
            profile_name="prowler",
            env=dict(os.environ),
            command=cmd,
            log_path=run_dir / "prowler.stdout.log",
            pid_path=run_dir / "prowler.pid",
        )

    def _build_result(
        self,
        invocation: StrixInvocation,
        *,
        returncode: int | None,
        error: str | None,
        stopped: bool,
    ) -> StrixRunResult:
        findings = parse_prowler_dir(invocation.run_dir)
        return StrixRunResult(
            returncode=returncode,
            findings=findings,
            metadata={"engine": "prowler", "returncode": returncode, "finding_count": len(findings)},
            report_path=None,
            error=error,
            stopped=stopped,
        )

    def _engine_completed(self, result: StrixRunResult) -> bool:
        """Prowler exits 0 (all checks pass) or 3 (failing checks found) on a healthy
        run; any other code means the scan itself errored (bad creds, etc.)."""
        return result.returncode in (0, _PROWLER_FINDINGS_EXIT)


# ---------------------------------------------------------------------------
# Prowler OCSF parsing (pure)
# ---------------------------------------------------------------------------
def parse_prowler_dir(run_dir: Path | str) -> list[ParsedVulnerability]:
    """Parse the OCSF JSON Prowler wrote under ``run_dir`` into normalized findings.

    Prowler names its OCSF file ``<filename>.ocsf.json`` (we pass ``--output-filename
    prowler``) but versions vary, so we glob any ``*.ocsf.json`` (and ``*.json`` as a
    fallback) and merge. Only FAIL findings become vulnerabilities."""
    d = Path(run_dir)
    if not d.exists():
        return []
    files = sorted(d.glob("*.ocsf.json")) or sorted(
        p for p in d.glob("*.json") if p.name not in ("run.json",)
    )
    out: list[ParsedVulnerability] = []
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
            log.warning("prowler.parse: skipping %s: %s", path, exc)
            continue
        for item in _ocsf_items(data):
            vuln = _vuln_from_ocsf(item)
            if vuln is not None:
                out.append(vuln)
    return out


def _ocsf_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("findings", "results", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        return [data]
    return []


def _ocsf_status(item: dict[str, Any]) -> str:
    """Prowler OCSF carries the check outcome as ``status_code`` (PASS/FAIL/MANUAL) or a
    ``status`` string; normalize to upper-case."""
    return str(_first(item, "status_code", "status", default="") or "").strip().upper()


def _vuln_from_ocsf(item: dict[str, Any]) -> ParsedVulnerability | None:
    """Map one OCSF detection finding to a ParsedVulnerability, or ``None`` for a
    non-FAIL (compliant / manual) check that is not a finding."""
    status = _ocsf_status(item)
    if status and status not in ("FAIL", "FAILED"):
        return None

    finding_info = item.get("finding_info") if isinstance(item.get("finding_info"), dict) else {}
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    remediation = item.get("remediation") if isinstance(item.get("remediation"), dict) else {}
    cloud = item.get("cloud") if isinstance(item.get("cloud"), dict) else {}
    resources = item.get("resources") if isinstance(item.get("resources"), list) else []

    title = _to_str(_first(finding_info, "title", default=None)) or _to_str(
        _first(item, "title", "message", default="Prowler finding")
    )
    # OCSF severity is a string ("Critical"…) and/or a numeric severity_id.
    severity = map_severity(_first(item, "severity", default=None) or _severity_from_id(item.get("severity_id")))
    check_id = _to_str(_first(metadata, "event_code", default=None) or _first(item, "check_id", default=None))
    endpoint = None
    if resources and isinstance(resources[0], dict):
        endpoint = _to_str(_first(resources[0], "uid", "name", "type", default=None))
    account = None
    if isinstance(cloud.get("account"), dict):
        account = _to_str(cloud["account"].get("uid") or cloud["account"].get("name"))

    evidence: dict[str, Any] = {
        "raw": item,
        "engine": "prowler",
        "check_id": check_id,
        "status": status or None,
        "description": _to_str(_first(item, "status_detail", "risk_details", default=None)
                               or _first(finding_info, "desc", default=None)),
        "remediation": _to_str(_first(remediation, "desc", "text", default=None)),
        "references": remediation.get("references") if isinstance(remediation.get("references"), list) else None,
        "account": account,
        "region": _to_str(_first(cloud, "region", default=None)),
        "resource_type": _to_str(resources[0].get("type")) if resources and isinstance(resources[0], dict) else None,
        "compliance": _first(item, "compliance", "unmapped", default=None),
        "severity_id": item.get("severity_id"),
    }
    return ParsedVulnerability(
        title=str(title),
        severity=severity,
        cwe=None,  # cloud misconfigurations map to compliance controls, not CWE
        endpoint=endpoint,
        payload=None,
        poc=_to_str(_first(item, "status_detail", default=None)),
        evidence={k: v for k, v in evidence.items() if v is not None or k == "raw"},
        raw=item,
    )


def _severity_from_id(severity_id: Any) -> str | None:
    """OCSF ``severity_id`` (0..6) → a severity string map_severity understands."""
    mapping = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}
    try:
        return mapping.get(int(severity_id))
    except (TypeError, ValueError):
        return None
