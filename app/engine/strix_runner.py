"""app/engine/strix_runner.py — Strix subprocess runner (Security-Ops Phase 2, spec §7).

Server-authoritative execution layer. Takes a Run that ``services.runs.start_run``
has ALREADY cleared through the authorization gate (``app.authz.gate.enforce_scope``)
for every one of its targets, and drives the open-source Strix engine
(``usestrix/strix``) as a sandboxed subprocess to actually perform the assessment.

Wiring follows spec §7 exactly:
  * ``STRIX_LLM=openai/<model>`` , ``LLM_API_BASE=<internal litellm>/v1`` ,
    ``LLM_API_KEY=<key>`` — routed **internal-direct over Tailscale/LAN, never via
    Cloudflare** (long autonomous runs 504 through the CF-fronted public gateway).
  * Sandbox image ``settings.strix_sandbox_image`` (default
    ``ghcr.io/usestrix/strix-sandbox:1.0.0``; needs the Docker socket).
  * ``STRIX_REASONING_EFFORT=none`` — the gateway's OpenRouter route rejects
    ``reasoning_effort`` (spec §7 gotcha).
  * CLI ``strix -n -m {quick|standard|deep} -t <target> --instruction-file <scope>``
    (optionally ``--scope-mode diff --diff-base <sha>``).
  * Outputs land under ``settings.runs_dir/<run.id>/`` :
    ``vulnerabilities.json`` , ``run.json`` (usage/cost), ``penetration_test_report.md`` .

Belt-and-suspenders only: the ``--instruction-file`` restates the scope to the
engine, but the GATE is the authority (spec §4). This module NEVER trusts Strix to
self-limit — it only ever spawns targets the server-side gate already approved, and
it re-checks the emergency stop before spawning.

Transaction model: ``execute`` runs as a **detached background worker** that owns its
own session (see ``execute_run`` / ``launch_run_background``) and therefore commits at
run-lifecycle boundaries so the API can observe RUNNING→COMPLETED/FAILED/STOPPED. The
pure helpers (``build_*`` / ``render_*`` / ``parse_*``) do no I/O against the DB and are
independently testable.

Dependency direction (no cycles): engine -> {core.config, core.errors, db.session,
models, schemas, repositories, audit.writer}. Nothing imports engine.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.errors import ConflictError, NotFoundError, ValidationAppError
from app.db.session import get_sessionmaker
from app.models.audit import AuditAction
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.run import Run, RunMode, RunStatus
from app.audit.writer import record_event
from app.repositories.engagements import EngagementRepository
from app.repositories.findings import FindingRepository
from app.repositories.runs import RunRepository

if TYPE_CHECKING:  # avoid runtime import weight / any cycle; only used for typing
    from app.auth.middleware import AuthUser
    from app.models.engagement import Engagement

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STRIX_BIN = "strix"
DEFAULT_PROFILE = "hybrid-local-sweep-verify"

# Run statuses that mean "nobody else should overwrite the terminal state".
_TERMINAL: frozenset[RunStatus] = frozenset(
    {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.STOPPED, RunStatus.DENIED}
)

# RunMode -> Strix `-m` flag (spec §7: {quick|standard|deep}). Explicit map so we do
# not depend on the enum's value casing.
_MODE_FLAG: dict[RunMode, str] = {
    RunMode.QUICK: "quick",
    RunMode.STANDARD: "standard",
    RunMode.DEEP: "deep",
}

# Strix severity string -> our FindingSeverity enum (tolerant, case-insensitive).
_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.CRITICAL,
    "crit": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "moderate": FindingSeverity.MEDIUM,
    "med": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
    "informational": FindingSeverity.INFO,
    "information": FindingSeverity.INFO,
    "none": FindingSeverity.INFO,
}

# In-process registry of live Strix subprocesses so an operator "stop" can find and
# terminate them (single-worker container; cross-worker stop uses the pid-file
# fallback below). Multi-worker coordination is Phase 3.
_RUNNING: dict[uuid.UUID, "asyncio.subprocess.Process"] = {}


# ---------------------------------------------------------------------------
# Model-profile routing (spec §7 hybrid: local sweep, strong verify)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelProfile:
    """A per-engagement hybrid profile: cheap/local ``sweep`` for breadth/recall,
    stronger ``verify`` for depth/precision + the client-facing report (spec §7)."""

    name: str
    sweep: str
    verify: str


MODEL_PROFILES: dict[str, ModelProfile] = {
    # default: local Qwen sweep, big *local* Qwen verifier (try before paying cloud).
    "hybrid-local-sweep-verify": ModelProfile(
        "hybrid-local-sweep-verify", "strix-qwen3.6-35b", "strix-qwen3.5-122b"
    ),
    # cheapest: single local model does both passes.
    "local-sweep": ModelProfile("local-sweep", "strix-qwen3.6-35b", "strix-qwen3.6-35b"),
    # local sweep, big-local verify (alias of the default's intent).
    "local-verify": ModelProfile("local-verify", "strix-qwen3.6-35b", "strix-qwen3.5-122b"),
    # hardest verification escalates to a cloud frontier model.
    "frontier-verify": ModelProfile("frontier-verify", "strix-qwen3.6-35b", "gpt-4o"),
}


def resolve_model_profile(name: str | None) -> ModelProfile:
    """Resolve a profile name to a :class:`ModelProfile`.

    Falls back to the default when empty; an unknown name is treated as a raw model id
    (single-model run) so an engagement can pin an exact model without a named profile.
    """
    if not name:
        return MODEL_PROFILES[DEFAULT_PROFILE]
    if name in MODEL_PROFILES:
        return MODEL_PROFILES[name]
    return ModelProfile(name=name, sweep=name, verify=name)


# ---------------------------------------------------------------------------
# Invocation building (pure) — env, command, instruction file
# ---------------------------------------------------------------------------


@dataclass
class StrixInvocation:
    """Everything needed to spawn one Strix subprocess for a run."""

    run_dir: Path
    instruction_path: Path
    model: str
    verify_model: str
    profile_name: str
    env: dict[str, str]
    command: list[str]
    log_path: Path
    pid_path: Path


def build_strix_env(
    *,
    model: str,
    base_url: str | None = None,
    api_key: str | None = None,
    sandbox_image: str | None = None,
    reasoning_effort: str = "none",
    config: Settings | None = None,
) -> dict[str, str]:
    """Build the subprocess environment wiring Strix to the INTERNAL litellm (spec §7).

    Inherits ``os.environ`` (for PATH / HOME / DOCKER_HOST so the sandbox can reach the
    Docker socket) and overlays the Strix + LLM keys. Reading ``os.environ`` here is the
    child-process environment — NOT app settings, which always come from ``settings``.
    """
    cfg = config or settings
    base_url = base_url or cfg.internal_litellm_base_url
    api_key = api_key if api_key is not None else cfg.internal_litellm_api_key
    sandbox_image = sandbox_image or cfg.strix_sandbox_image
    # STRIX_LLM must be provider-qualified; litellm treats the internal proxy as openai.
    strix_llm = model if "/" in model else f"openai/{model}"

    env: dict[str, str] = dict(os.environ)
    env.update(
        {
            "STRIX_LLM": strix_llm,
            "LLM_API_BASE": base_url,
            "LLM_API_KEY": api_key or "",
            "STRIX_SANDBOX_IMAGE": sandbox_image,
            # §7 gotcha: the gateway's OpenRouter route rejects reasoning_effort.
            "STRIX_REASONING_EFFORT": reasoning_effort,
        }
    )
    if not api_key:
        log.warning(
            "strix.env: internal litellm api key is empty "
            "(settings.internal_litellm_api_key unset); the proxy may reject calls"
        )
    return env


def _mode_flag(mode: RunMode | str) -> str:
    if isinstance(mode, RunMode):
        return _MODE_FLAG.get(mode, "standard")
    try:
        return _MODE_FLAG[RunMode(mode)]
    except Exception:  # pragma: no cover - defensive: unknown raw string
        return str(mode).lower()


def build_strix_command(
    *,
    mode: RunMode | str,
    targets: Iterable[str],
    instruction_path: Path | str,
    scope_mode: str | None = None,
    diff_base: str | None = None,
    extra_args: Iterable[str] | None = None,
) -> list[str]:
    """Build the Strix CLI argv (spec §7).

    ``strix -n -m {quick|standard|deep} -t <t1> [-t <t2> ...] --instruction-file <scope>
    [--scope-mode diff --diff-base <sha>]``. The instruction file restates scope as
    defense-in-depth; the server-side gate remains authoritative.
    """
    targets = [t for t in targets if t]
    if not targets:
        raise ValidationAppError("cannot build a Strix command with no targets")
    cmd: list[str] = [STRIX_BIN, "-n", "-m", _mode_flag(mode)]
    for target in targets:
        cmd += ["-t", target]
    cmd += ["--instruction-file", str(instruction_path)]
    if scope_mode:
        cmd += ["--scope-mode", scope_mode]
        if diff_base:
            cmd += ["--diff-base", diff_base]
    if extra_args:
        cmd += [str(a) for a in extra_args]
    return cmd


def _rule_str(rule: Any) -> str:
    if isinstance(rule, dict):
        kind = rule.get("kind")
        value = rule.get("value")
        return f"{kind}: {value}" if kind else str(value)
    return str(rule)


def render_instruction_file(engagement: "Engagement", targets: list[str]) -> str:
    """Render the ``--instruction-file`` restating the authorized scope to the engine.

    Sourced from the engagement's ``scope`` (in_scope/exclusions) + ``rules_of_engagement``
    JSONB and the concrete gate-approved ``targets`` for this run. This is belt-and-
    suspenders (spec §4/§7); the server gate is the real control.
    """
    scope = getattr(engagement, "scope", None) or {}
    roe = getattr(engagement, "rules_of_engagement", None) or scope.get("rules_of_engagement") or {}
    in_scope = scope.get("in_scope") or []
    exclusions = scope.get("exclusions") or []
    name = getattr(engagement, "name", "engagement")
    eid = getattr(engagement, "id", "")

    lines: list[str] = [
        f"# Rules of Engagement — {name}",
        "",
        f"Engagement ID: {eid}",
        "",
        "## AUTHORIZATION",
        "This is an AUTHORIZED security assessment governed by a server-side scope gate.",
        "You may test ONLY the assets listed under 'Run targets' / 'In scope' below.",
        "Testing anything not explicitly in scope — or anything under 'Exclusions' — is FORBIDDEN.",
        "The Security-Ops server independently enforces this scope and may terminate this run "
        "at any time; honor SIGTERM immediately.",
        "",
        "## Run targets (authorized for this run)",
    ]
    lines += [f"- {t}" for t in targets] or ["- (none)"]

    lines += ["", "## In scope"]
    if in_scope:
        lines += [f"- {_rule_str(r)}" for r in in_scope]
    else:
        lines.append("- (see Run targets)")

    lines += ["", "## Exclusions (NEVER touch)"]
    if exclusions:
        lines += [f"- {_rule_str(r)}" for r in exclusions]
    else:
        lines.append("- (none listed — treat everything outside scope as excluded)")

    lines += ["", "## Constraints (rules of engagement)"]
    intensity = roe.get("intensity")
    if intensity:
        lines.append(f"- Intensity: {intensity}")
    allowed = roe.get("allowed_vuln_classes")
    if allowed:
        lines.append(f"- Allowed vulnerability classes: {', '.join(map(str, allowed))}")
    tw_start, tw_end = roe.get("time_window_start"), roe.get("time_window_end")
    if tw_start or tw_end:
        lines.append(f"- Time window: {tw_start or 'open'} .. {tw_end or 'open'}")
    max_conc = roe.get("max_concurrency")
    if max_conc:
        lines.append(f"- Max concurrency: {max_conc}")
    lines += [
        "- Do not exfiltrate real user data; capture the minimal proof-of-concept only.",
        "- Do not perform destructive actions (data deletion, DoS, ransomware simulation) "
        "unless explicitly authorized above.",
        "",
        "## Emergency stop",
        "If the engagement is paused or stopped server-side the process will be terminated. "
        "Do not attempt to persist or evade termination.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Output parsing (pure) — vulnerabilities.json, run.json
# ---------------------------------------------------------------------------


@dataclass
class ParsedVulnerability:
    """One normalized finding parsed from Strix's ``vulnerabilities.json``."""

    title: str
    severity: FindingSeverity
    cwe: str | None
    endpoint: str | None
    payload: str | None
    poc: str | None
    evidence: dict[str, Any]
    raw: dict[str, Any]

    def to_finding_fields(
        self, *, run: Run, engagement: "Engagement", verified_by: str | None = None
    ) -> dict[str, Any]:
        """Map to ``FindingRepository.create(**fields)`` kwargs (denormalized FKs per
        the findings table: run_id, engagement_id, org_id)."""
        return {
            "run_id": run.id,
            "engagement_id": engagement.id,
            "org_id": run.org_id,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "endpoint": self.endpoint,
            "payload": self.payload,
            "evidence": self.evidence,
            "poc": self.poc,
            "verified_by": verified_by,
            "status": FindingStatus.NEW,
        }


@dataclass
class StrixRunResult:
    """Outcome of one subprocess execution (parsed, pre-persistence)."""

    returncode: int | None
    findings: list[ParsedVulnerability]
    metadata: dict[str, Any]
    report_path: str | None
    error: str | None = None
    stopped: bool = False


def map_severity(raw: Any) -> FindingSeverity:
    """Map a Strix severity string to :class:`FindingSeverity`.

    Unknown / missing severities default to MEDIUM so they surface for human review
    rather than being silently filtered as INFO (the raw value is retained in evidence).
    """
    if raw is None:
        return FindingSeverity.MEDIUM
    return _SEVERITY_MAP.get(str(raw).strip().lower(), FindingSeverity.MEDIUM)


def _first(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in d and d[key] not in (None, ""):
            return d[key]
    return default


def _to_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return str(value)


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_cwe(value: Any) -> str | None:
    if value is None or value == "":
        return None
    text = str(value).strip()
    return f"CWE-{text}" if text.isdigit() else text


def _vuln_from_dict(item: dict[str, Any]) -> ParsedVulnerability:
    raw_severity = _first(item, "severity", "risk", "sev")
    description = _first(item, "description", "details", "detail", "summary")
    remediation = _first(item, "remediation", "fix", "mitigation", "recommendation")
    evidence: dict[str, Any] = {
        "raw": item,
        "raw_severity": raw_severity,
        "description": description,
        "remediation": remediation,
        "references": _first(item, "references", "refs"),
        "confidence": _first(item, "confidence", "certainty"),
    }
    return ParsedVulnerability(
        title=str(_first(item, "title", "name", "summary", "vulnerability", default="Untitled finding")),
        severity=map_severity(raw_severity),
        cwe=_normalize_cwe(_first(item, "cwe", "cwe_id", "cweId")),
        endpoint=_to_str(_first(item, "endpoint", "url", "location", "target", "affected_url")),
        payload=_to_str(_first(item, "payload", "request", "payloads", "exploit")),
        poc=_to_str(_first(item, "poc", "proof_of_concept", "proof", "reproduction", "steps")),
        evidence={k: v for k, v in evidence.items() if v is not None or k == "raw"},
        raw=item,
    )


def _vuln_items(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("vulnerabilities", "findings", "results", "items", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return value
        return [data]  # a single vuln object
    return []


def parse_vulnerabilities(run_dir: Path | str) -> list[ParsedVulnerability]:
    """Parse ``<run_dir>/vulnerabilities.json`` into normalized findings (tolerant of
    list vs ``{"vulnerabilities": [...]}`` shapes and heterogeneous key names)."""
    path = Path(run_dir) / "vulnerabilities.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("strix.parse.vulnerabilities failed for %s: %s", path, exc)
        return []
    return [_vuln_from_dict(it) for it in _vuln_items(data) if isinstance(it, dict)]


def parse_run_metadata(run_dir: Path | str) -> dict[str, Any]:
    """Parse ``<run_dir>/run.json`` (Strix run id, usage, cost) tolerantly."""
    path = Path(run_dir) / "run.json"
    empty = {"strix_run_id": None, "cost_usd": None, "usage": None, "raw": {}}
    if not path.exists():
        return dict(empty)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("strix.parse.run_json failed for %s: %s", path, exc)
        return dict(empty)
    if not isinstance(raw, dict):
        raw = {"value": raw}
    strix_run_id = _first(raw, "run_id", "id", "strix_run_id", "runId")
    cost = _first(raw, "cost_usd", "cost", "total_cost", "totalCost", "total_cost_usd")
    usage = _first(raw, "usage", "token_usage", "tokens", "usage_summary")
    return {
        "strix_run_id": str(strix_run_id) if strix_run_id is not None else None,
        "cost_usd": _to_float(cost),
        "usage": usage if isinstance(usage, dict) else ({"raw": usage} if usage is not None else None),
        "raw": raw,
    }


def _report_path(run_dir: Path) -> str | None:
    report = Path(run_dir) / "penetration_test_report.md"
    return str(report) if report.exists() else None


# ---------------------------------------------------------------------------
# Subprocess lifecycle helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _write_pid(pid_path: Path, pid: int) -> None:
    try:
        pid_path.write_text(str(pid), encoding="utf-8")
    except OSError as exc:  # pragma: no cover - non-fatal
        log.warning("strix.pid write failed %s: %s", pid_path, exc)


def _read_pid(pid_path: Path) -> int | None:
    try:
        return int(pid_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _remove_pid(pid_path: Path) -> None:
    try:
        pid_path.unlink(missing_ok=True)
    except OSError:  # pragma: no cover - non-fatal
        pass


async def _terminate(proc: "asyncio.subprocess.Process", grace: float = 10.0) -> None:
    """SIGTERM then (after ``grace``) SIGKILL a subprocess; idempotent."""
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=grace)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            return
        await proc.wait()


async def stop_run_process(run_id: uuid.UUID, *, config: Settings | None = None) -> bool:
    """Terminate the live Strix subprocess for ``run_id`` (process control only — the
    DB status flip + RUN_STOPPED audit are owned by ``services.runs.stop_run``).

    Tries the in-process registry first, then the on-disk pid file (cross-task/worker
    fallback). Returns True if a termination signal was delivered.
    """
    cfg = config or settings
    proc = _RUNNING.get(run_id)
    if proc is not None and proc.returncode is None:
        await _terminate(proc)
        return True
    pid = _read_pid(Path(cfg.runs_dir) / str(run_id) / "strix.pid")
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            return True
        except (ProcessLookupError, PermissionError) as exc:
            log.warning("strix.stop pid=%s failed: %s", pid, exc)
    return False


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


class StrixRunner:
    """Drives one gate-approved :class:`Run` through the Strix engine.

    Construct with the (background-worker) session; ``execute`` owns the transaction and
    commits at lifecycle boundaries. The runner never re-opens the gate — it trusts that
    ``services.runs.start_run`` cleared every target — but it *does* re-honor the
    emergency stop before spawning (defense-in-depth, spec §11).
    """

    def __init__(self, session: AsyncSession, *, config: Settings | None = None) -> None:
        self.session = session
        self.settings = config or settings
        self.runs = RunRepository(session)
        self.findings = FindingRepository(session)

    # -- preparation (filesystem only) ------------------------------------

    def prepare(
        self,
        *,
        run: Run,
        engagement: "Engagement",
        scope_mode: str | None = None,
        diff_base: str | None = None,
    ) -> StrixInvocation:
        """Create the run dir, write the scope instruction file, and build env + argv."""
        targets = [t for t in (run.targets or []) if t]
        if not targets:
            raise ValidationAppError("run has no targets to scan")

        profile_name = run.model_profile or getattr(engagement, "model_profile", None) or DEFAULT_PROFILE
        profile = resolve_model_profile(profile_name)

        run_dir = Path(self.settings.runs_dir) / str(run.id)
        run_dir.mkdir(parents=True, exist_ok=True)

        instruction_path = run_dir / "scope_instructions.md"
        instruction_path.write_text(render_instruction_file(engagement, targets), encoding="utf-8")

        env = build_strix_env(model=profile.sweep, config=self.settings)
        command = build_strix_command(
            mode=run.mode,
            targets=targets,
            instruction_path=instruction_path,
            scope_mode=scope_mode,
            diff_base=diff_base,
        )
        return StrixInvocation(
            run_dir=run_dir,
            instruction_path=instruction_path,
            model=profile.sweep,
            verify_model=profile.verify,
            profile_name=profile.name,
            env=env,
            command=command,
            log_path=run_dir / "strix.stdout.log",
            pid_path=run_dir / "strix.pid",
        )

    # -- full execution ---------------------------------------------------

    async def execute(
        self,
        *,
        run: Run,
        engagement: "Engagement",
        actor: "AuthUser | str" = "system:strix-runner",
        timeout: float | None = None,
        scope_mode: str | None = None,
        diff_base: str | None = None,
    ) -> Run:
        """Run the full pipeline: prepare -> RUNNING -> spawn+wait -> parse -> persist
        findings -> terminal status. Commits at each lifecycle boundary. Returns the Run.
        """
        log.info("strix.execute.begin run=%s engagement=%s", run.id, engagement.id)

        # Belt-and-suspenders emergency-stop re-check before we spawn anything (spec §11).
        if self.settings.emergency_stop_all or getattr(engagement, "emergency_stopped", False):
            log.warning("strix.execute.blocked-emergency-stop run=%s", run.id)
            return await self._terminal(
                run,
                engagement,
                actor,
                status=RunStatus.STOPPED,
                audit=AuditAction.RUN_STOPPED,
                decision="stopped",
                reason="emergency_stop_engaged",
                error="emergency stop engaged before launch",
            )

        if run.status != RunStatus.PENDING:
            raise ConflictError(
                f"run {run.id} is not PENDING (status={getattr(run.status, 'value', run.status)})"
            )

        invocation = self.prepare(
            run=run, engagement=engagement, scope_mode=scope_mode, diff_base=diff_base
        )

        run = await self.runs.set_status(
            run.id,
            RunStatus.RUNNING,
            started_at=_now(),
            model_profile=invocation.profile_name,
        )
        await self.session.commit()
        log.info(
            "strix.execute.running run=%s model=%s cmd=%s",
            run.id,
            invocation.model,
            " ".join(invocation.command),
        )

        result = await self._spawn_and_wait(invocation, run=run, timeout=timeout)

        # Persist findings even for a stopped/failed run — partial evidence still matters.
        findings = await self._store_findings(
            result, run=run, engagement=engagement, actor=actor, verified_by=invocation.model
        )

        # If an operator stop already set a terminal status, don't clobber it.
        fresh = await self.runs.get(run.id)
        if fresh is not None and fresh.status in _TERMINAL:
            log.info(
                "strix.execute.already-terminal run=%s status=%s findings=%d",
                run.id,
                getattr(fresh.status, "value", fresh.status),
                len(findings),
            )
            await self.session.commit()
            return fresh

        if result.stopped:
            return await self._terminal(
                run,
                engagement,
                actor,
                status=RunStatus.STOPPED,
                audit=AuditAction.RUN_STOPPED,
                decision="stopped",
                reason=result.error or "stopped",
                error=result.error,
                metadata=result.metadata,
                report_path=result.report_path,
                findings_count=len(findings),
            )

        failed = bool(result.error) or (result.returncode not in (0, None))
        if failed:
            return await self._terminal(
                run,
                engagement,
                actor,
                status=RunStatus.FAILED,
                audit=AuditAction.RUN_COMPLETED,
                decision="failed",
                reason=result.error or f"strix exited {result.returncode}",
                error=result.error or f"strix exited with code {result.returncode}",
                metadata=result.metadata,
                report_path=result.report_path,
                findings_count=len(findings),
            )

        return await self._terminal(
            run,
            engagement,
            actor,
            status=RunStatus.COMPLETED,
            audit=AuditAction.RUN_COMPLETED,
            decision="completed",
            reason=None,
            error=None,
            metadata=result.metadata,
            report_path=result.report_path,
            findings_count=len(findings),
        )

    # -- internals --------------------------------------------------------

    async def _spawn_and_wait(
        self, invocation: StrixInvocation, *, run: Run, timeout: float | None
    ) -> StrixRunResult:
        """Spawn the Strix subprocess, stream stdout/stderr to a log file, and wait.

        Handles timeout (terminate + error) and cancellation (terminate + mark stopped).
        Always parses whatever outputs Strix produced before returning.
        """
        try:
            log_file = open(invocation.log_path, "wb")
        except OSError as exc:
            return StrixRunResult(
                returncode=None, findings=[], metadata={}, report_path=None,
                error=f"could not open run log {invocation.log_path}: {exc}",
            )

        stopped = False
        error: str | None = None
        returncode: int | None = None
        try:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *invocation.command,
                    cwd=str(invocation.run_dir),
                    env=invocation.env,
                    stdout=log_file,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except FileNotFoundError:
                return StrixRunResult(
                    returncode=127, findings=[], metadata={"returncode": 127},
                    report_path=None,
                    error=f"strix binary not found on PATH: {invocation.command[0]!r}",
                )

            _RUNNING[run.id] = proc
            _write_pid(invocation.pid_path, proc.pid)
            log.info("strix.spawn run=%s pid=%s", run.id, proc.pid)

            try:
                if timeout:
                    returncode = await asyncio.wait_for(proc.wait(), timeout=timeout)
                else:
                    returncode = await proc.wait()
            except asyncio.TimeoutError:
                await _terminate(proc)
                returncode = proc.returncode
                stopped = True
                error = f"strix run timed out after {timeout}s"
                log.warning("strix.timeout run=%s", run.id)
            except asyncio.CancelledError:
                await _terminate(proc)
                raise
        finally:
            _RUNNING.pop(run.id, None)
            _remove_pid(invocation.pid_path)
            try:
                log_file.close()
            except OSError:  # pragma: no cover
                pass

        findings = parse_vulnerabilities(invocation.run_dir)
        metadata = parse_run_metadata(invocation.run_dir)
        metadata["returncode"] = returncode
        return StrixRunResult(
            returncode=returncode,
            findings=findings,
            metadata=metadata,
            report_path=_report_path(invocation.run_dir),
            error=error,
            stopped=stopped,
        )

    async def _store_findings(
        self,
        result: StrixRunResult,
        *,
        run: Run,
        engagement: "Engagement",
        actor: "AuthUser | str",
        verified_by: str | None,
    ) -> list[Finding]:
        created: list[Finding] = []
        for vuln in result.findings:
            fields = vuln.to_finding_fields(run=run, engagement=engagement, verified_by=verified_by)
            finding = await self.findings.create(**fields)
            created.append(finding)
            await record_event(
                self.session,
                action=AuditAction.FINDING_RECORDED,
                actor=actor,
                org_id=run.org_id,
                engagement_id=engagement.id,
                run_id=run.id,
                target=vuln.endpoint,
                detail={
                    "title": vuln.title,
                    "severity": vuln.severity.value,
                    "cwe": vuln.cwe,
                },
            )
        if created:
            await self.session.flush()
            log.info("strix.findings.stored run=%s count=%d", run.id, len(created))
        return created

    async def _terminal(
        self,
        run: Run,
        engagement: "Engagement",
        actor: "AuthUser | str",
        *,
        status: RunStatus,
        audit: AuditAction,
        decision: str | None,
        reason: str | None,
        error: str | None,
        metadata: dict[str, Any] | None = None,
        report_path: str | None = None,
        findings_count: int = 0,
    ) -> Run:
        """Set a terminal run status, write the lifecycle audit event, and commit."""
        md = metadata or {}
        run = await self.runs.set_status(
            run.id,
            status,
            ended_at=_now(),
            error=error,
            strix_run_id=md.get("strix_run_id"),
            cost_usd=md.get("cost_usd"),
            usage=md.get("usage"),
            report_path=report_path,
        )
        await record_event(
            self.session,
            action=audit,
            actor=actor,
            org_id=run.org_id,
            engagement_id=engagement.id,
            run_id=run.id,
            decision=decision,
            reason=reason,
            detail={
                "status": status.value,
                "returncode": md.get("returncode"),
                "cost_usd": md.get("cost_usd"),
                "findings": findings_count,
                "report_path": report_path,
                "error": error,
            },
        )
        await self.session.commit()
        log.info(
            "strix.execute.done run=%s status=%s findings=%d cost=%s",
            run.id,
            status.value,
            findings_count,
            md.get("cost_usd"),
        )
        return run


# ---------------------------------------------------------------------------
# Convenience entrypoints (own their own session — background-worker pattern)
# ---------------------------------------------------------------------------


async def execute_run(
    *,
    run_id: uuid.UUID,
    engagement_id: uuid.UUID,
    org_id: uuid.UUID | None = None,
    actor: "AuthUser | str" = "system:strix-runner",
    timeout: float | None = None,
    scope_mode: str | None = None,
    diff_base: str | None = None,
) -> Run:
    """Load the run + engagement in a fresh session and execute end-to-end.

    This is the natural target for ``services.runs.start_run`` to schedule after the
    gate passes and the PENDING run is committed. It owns its own session because the
    request session that created the run is already closed by the time the (30+ min)
    scan runs.

    RLS: the detached worker has NO request context, so ``org_id`` MUST be threaded
    in (``start_run`` supplies ``run.org_id``). It is bound to the session GUC
    *before* the first query — otherwise, on a Postgres instance with the
    ``0002_org_rls`` policies active, the run/engagement/findings rows would be
    invisible/unwritable to this connection (fail-closed). The context is cleared
    on exit so the pooled connection carries no tenant state to its next borrower.
    """
    from app.db.rls import clear_org_context, set_org_context  # lazy: avoid cycle

    async with get_sessionmaker()() as session:
        if org_id is not None:
            await set_org_context(session, org_id)
        try:
            runner = StrixRunner(session)
            run = await runner.runs.get(run_id)
            if run is None:
                raise NotFoundError(f"run {run_id} not found")
            engagement = await EngagementRepository(session).get(engagement_id)
            if engagement is None:
                raise NotFoundError(f"engagement {engagement_id} not found")
            return await runner.execute(
                run=run,
                engagement=engagement,
                actor=actor,
                timeout=timeout,
                scope_mode=scope_mode,
                diff_base=diff_base,
            )
        finally:
            if org_id is not None:
                try:
                    await clear_org_context(session)
                    await session.commit()
                except Exception:  # noqa: BLE001 - teardown must not mask the run result
                    log.warning("strix.execute: failed to clear org context", exc_info=True)


def launch_run_background(
    *,
    run_id: uuid.UUID,
    engagement_id: uuid.UUID,
    org_id: uuid.UUID | None = None,
    actor: "AuthUser | str" = "system:strix-runner",
    timeout: float | None = None,
    scope_mode: str | None = None,
    diff_base: str | None = None,
) -> "asyncio.Task[None]":
    """Fire-and-forget the run as an asyncio task (detached from the request lifecycle).

    Returns the task so a caller/test can await it. Exceptions are logged, never raised
    into the event loop's default handler. ``org_id`` is threaded through to bind the
    worker's session to the tenant under RLS (see :func:`execute_run`).
    """

    async def _worker() -> None:
        try:
            await execute_run(
                run_id=run_id,
                engagement_id=engagement_id,
                org_id=org_id,
                actor=actor,
                timeout=timeout,
                scope_mode=scope_mode,
                diff_base=diff_base,
            )
        except Exception:  # noqa: BLE001 - background task must not crash the loop
            log.exception("strix.background.failed run=%s", run_id)

    return asyncio.create_task(_worker())
