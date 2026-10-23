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
overrides the execution/preparation boundary as well as the result seams:

* :meth:`prepare` — build the ``prowler <provider>`` command + run dir (no LLM env).
* :meth:`execute` / :meth:`_spawn_and_wait` — gate, mint, isolate and clean credentials.
* :meth:`_build_result` — parse Prowler's OCSF JSON into normalized findings (FAILs only;
  PASS/MANUAL checks are compliant/non-findings).
* :meth:`_engine_completed` — Prowler exits ``0`` when all checks pass and ``3`` when it
  found failing checks (both are a successful *run*); any other code is an error.

Runtime AWS credentials are minted after rechecking the engagement/attestation gate,
and are passed only to this run's Prowler subprocess. Each invocation scans exactly
one AWS account. GCP/Azure fail closed until their runtime credentials are implemented.
Raw tool output is private and temporary; only scrubbed findings reach storage and
reports. Tool stdout/stderr is discarded because it can echo credentials; the shared
runner still records lifecycle events. Temporary credentials are never refreshed.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, Iterable

from app.authz.cloud_proof import parse_cloud_value
from app.authz.errors import AuthorizationDenied
from app.authz.gate import enforce_scope
from app.core.errors import ConflictError
from app.engine.cloud_credentials import (
    credential_values,
    isolated_prowler_env,
    scrub_cloud_output,
)
from app.engine.credential_minter import (
    CredentialMintError,
    _find_cloud_target,
    mint_prowler_credentials,
)

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
from app.models.audit import AuditAction
from app.models.engagement import Engagement
from app.models.run import RunMode, RunStatus

if TYPE_CHECKING:  # pragma: no cover
    from app.auth.sso import AuthUser
    from app.models.run import Run

log = logging.getLogger("secops.engine.prowler")

PROWLER_BIN = "prowler"

# Prowler exits 3 (not 0) when it found failing checks — a successful scan that has
# findings, analogous to Strix's non-zero-on-vulns convention (hence the seam).
_PROWLER_FINDINGS_EXIT = 3


def _provider_account(target: str) -> tuple[str, str]:
    """Reject malformed values rather than falling back to the host AWS identity."""
    return parse_cloud_value(target)


class ProwlerRunner(StrixRunner):
    """Prowler engine — cloud-account posture (CSPM) behind the authorization gate."""

    async def execute(
        self,
        *,
        run: Run,
        engagement: Engagement,
        actor: AuthUser | str = "system:prowler-runner",
        timeout: float | None = None,
        scope_mode: str | None = None,
        diff_base: str | None = None,
    ) -> Run:
        if getattr(self, "_active_run_id", None) is not None:
            raise ConflictError("Prowler runner already has an active invocation")
        if run.status != RunStatus.PENDING:
            raise ConflictError("Prowler run is not PENDING")
        if run.engagement_id != engagement.id or run.org_id != engagement.org_id:
            raise CredentialMintError("run and engagement organization do not match")

        self._active_run_id = run.id
        self._run_context = (run.org_id, run.engagement_id, tuple(run.targets or []))
        self._credential_env = {}
        self._output_dir = None
        try:
            targets = list(run.targets or [])
            if len(targets) != 1:
                raise CredentialMintError(
                    "Prowler requires exactly one cloud account per run"
                )
            self._credential_env = await mint_prowler_credentials(
                self.session,
                org_id=run.org_id,
                engagement_id=engagement.id,
                target_value=targets[0],
                actor=actor,
                run_id=run.id,
            )
            # Re-read queued state after the STS wait, before changing run status.
            await self.session.refresh(run)
            await self.session.refresh(engagement)
            if self._run_context != (
                run.org_id,
                run.engagement_id,
                tuple(run.targets or []),
            ):
                raise CredentialMintError(
                    "cloud run context changed while minting credentials"
                )
            run_dir = Path(self.settings.runs_dir) / str(run.id)
            run_dir.mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix=".prowler-", dir=run_dir) as raw_dir:
                self._output_dir = Path(raw_dir)
                return await super().execute(
                    run=run,
                    engagement=engagement,
                    actor=actor,
                    timeout=timeout,
                    scope_mode=scope_mode,
                    diff_base=diff_base,
                )
        except AuthorizationDenied as exc:
            return await self._terminal(
                run,
                engagement,
                actor,
                status=RunStatus.DENIED,
                audit=AuditAction.RUN_COMPLETED,
                decision="denied",
                reason=exc.code,
                error=f"cloud authorization denied: {exc.code}",
            )
        except CredentialMintError as exc:
            # CredentialMintError contains only our fixed, credential-free messages.
            return await self._terminal(
                run,
                engagement,
                actor,
                status=RunStatus.FAILED,
                audit=AuditAction.RUN_COMPLETED,
                decision="failed",
                reason="cloud_credentials_unavailable",
                error=str(exc),
            )
        finally:
            self._credential_env.clear()
            self._active_run_id = None
            self._run_context = None
            self._output_dir = None

    def prepare(
        self,
        *,
        run: "Run",
        engagement: "Engagement",
        scope_mode: str | None = None,
        diff_base: str | None = None,
    ) -> StrixInvocation:
        if (
            getattr(self, "_active_run_id", None) != run.id
            or not getattr(self, "_credential_env", None)
            or self._output_dir is None
        ):
            raise CredentialMintError(
                "Prowler preparation requires this run's credentials"
            )
        run_dir = Path(self.settings.runs_dir) / str(run.id)
        run_dir.mkdir(parents=True, exist_ok=True)

        targets = list(run.targets or [])
        if len(targets) != 1 or _provider_account(targets[0])[0] != "aws":
            raise CredentialMintError("Prowler requires exactly one AWS account")

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
            "aws",
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            str(self._output_dir),
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
        home = self._output_dir / "home"
        home.mkdir(mode=0o700)
        return StrixInvocation(
            run_dir=run_dir,
            instruction_path=scope_note,
            model="prowler",
            verify_model=verify_model,
            profile_name="prowler",
            env=isolated_prowler_env(
                self._credential_env, home=home, ambient=os.environ
            ),
            command=cmd,
            log_path=run_dir / "prowler.stdout.log",
            pid_path=run_dir / "prowler.pid",
            capture_output=False,
        )

    async def _spawn_and_wait(
        self, invocation: StrixInvocation, *, run: Run, timeout: float | None
    ) -> StrixRunResult:
        try:
            await self.session.refresh(run)
            if self._run_context != (
                run.org_id,
                run.engagement_id,
                tuple(run.targets or []),
            ):
                raise CredentialMintError("cloud run context changed before launch")
            if run.status != RunStatus.RUNNING:
                return StrixRunResult(
                    returncode=None,
                    findings=[],
                    metadata={},
                    report_path=None,
                    stopped=True,
                    error="cloud run stopped before launch",
                )
            engagement = await self.session.get(
                Engagement, run.engagement_id, populate_existing=True
            )
            if engagement is None or engagement.org_id != run.org_id:
                raise CredentialMintError(
                    "engagement does not belong to the run organization"
                )
            # Recheck after minting/committing: queue delay or STS latency must not
            # turn a revoked/paused target into an authorized subprocess launch.
            await enforce_scope(
                self.session,
                engagement.id,
                run.targets[0],
                actor="system:prowler-runner",
                run_id=run.id,
            )
            target_value = "aws:" + _provider_account(run.targets[0])[1]
            if await _find_cloud_target(self.session, run.org_id, target_value) is None:
                raise CredentialMintError(
                    "cloud role attestation changed before launch"
                )
            return await super()._spawn_and_wait(invocation, run=run, timeout=timeout)
        finally:
            # The invocation must not retain credentials after success, timeout,
            # cancellation, or a failed recheck.
            invocation.env.clear()

    def _build_result(
        self,
        invocation: StrixInvocation,
        *,
        returncode: int | None,
        error: str | None,
        stopped: bool,
    ) -> StrixRunResult:
        secrets = credential_values(invocation.env)
        findings = parse_prowler_dir(self._output_dir, secrets=secrets)
        return StrixRunResult(
            returncode=returncode,
            findings=findings,
            metadata={
                "engine": "prowler",
                "returncode": returncode,
                "finding_count": len(findings),
            },
            report_path=None,
            error=scrub_cloud_output(error, secrets),
            stopped=stopped,
        )

    def _engine_completed(self, result: StrixRunResult) -> bool:
        """Prowler exits 0 (all checks pass) or 3 (failing checks found) on a healthy
        run; any other code means the scan itself errored (bad creds, etc.)."""
        return result.returncode in (0, _PROWLER_FINDINGS_EXIT)


# ---------------------------------------------------------------------------
# Prowler OCSF parsing (pure)
# ---------------------------------------------------------------------------
def parse_prowler_dir(
    run_dir: Path | str, *, secrets: Iterable[str] = ()
) -> list[ParsedVulnerability]:
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
        except (OSError, UnicodeError, json.JSONDecodeError):  # defensive
            log.warning("prowler.parse: skipping unreadable JSON output")
            continue
        for item in _ocsf_items(scrub_cloud_output(data, secrets)):
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

    finding_info = (
        item.get("finding_info") if isinstance(item.get("finding_info"), dict) else {}
    )
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    remediation = (
        item.get("remediation") if isinstance(item.get("remediation"), dict) else {}
    )
    cloud = item.get("cloud") if isinstance(item.get("cloud"), dict) else {}
    resources = item.get("resources") if isinstance(item.get("resources"), list) else []

    title = _to_str(_first(finding_info, "title", default=None)) or _to_str(
        _first(item, "title", "message", default="Prowler finding")
    )
    # OCSF severity is a string ("Critical"…) and/or a numeric severity_id.
    severity = map_severity(
        _first(item, "severity", default=None)
        or _severity_from_id(item.get("severity_id"))
    )
    check_id = _to_str(
        _first(metadata, "event_code", default=None)
        or _first(item, "check_id", default=None)
    )
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
        "description": _to_str(
            _first(item, "status_detail", "risk_details", default=None)
            or _first(finding_info, "desc", default=None)
        ),
        "remediation": _to_str(_first(remediation, "desc", "text", default=None)),
        "references": remediation.get("references")
        if isinstance(remediation.get("references"), list)
        else None,
        "account": account,
        "region": _to_str(_first(cloud, "region", default=None)),
        "resource_type": _to_str(resources[0].get("type"))
        if resources and isinstance(resources[0], dict)
        else None,
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
    mapping = {
        1: "info",
        2: "low",
        3: "medium",
        4: "high",
        5: "critical",
        6: "critical",
    }
    try:
        return mapping.get(int(severity_id))
    except (TypeError, ValueError):
        return None
