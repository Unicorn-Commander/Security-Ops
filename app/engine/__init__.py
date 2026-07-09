"""app/engine — Security-Ops offensive execution + hand-off layer (Phase 2, spec §7/§8).

Wraps the embedded Strix engine as a sandboxed subprocess (``strix_runner``) and hands
confirmed findings to Brigade agents for triage/remediation (``brigade_handoff``). The
authorization gate (``app.authz``) decides *whether* a target may be touched; this layer
only ever runs what the gate already cleared and never trusts the engine to self-limit.
"""

from __future__ import annotations

from app.engine.strix_runner import (
    DEFAULT_PROFILE,
    MODEL_PROFILES,
    ModelProfile,
    ParsedVulnerability,
    StrixInvocation,
    StrixRunResult,
    StrixRunner,
    build_strix_command,
    build_strix_env,
    execute_run,
    launch_run_background,
    map_severity,
    parse_run_metadata,
    parse_vulnerabilities,
    render_instruction_file,
    resolve_model_profile,
    stop_run_process,
)
from app.engine.opengrep_runner import OpengrepRunner
from app.engine.naabu_runner import NaabuRunner
from app.engine.zap_runner import ZapRunner
from app.engine.enrich import enrich_cves
from app.engine.brigade_handoff import (
    BRIGADE_HANDOFF_AGENT,
    BrigadeHandoffClient,
    BrigadeHandoffPayload,
    HandoffError,
    HandoffNotConfigured,
    build_handoff_payload,
    default_client,
    handoff_finding,
)

__all__ = [
    # strix_runner
    "DEFAULT_PROFILE",
    "MODEL_PROFILES",
    "ModelProfile",
    "ParsedVulnerability",
    "OpengrepRunner",
    "NaabuRunner",
    "ZapRunner",
    "StrixInvocation",
    "StrixRunResult",
    "StrixRunner",
    "build_strix_command",
    "build_strix_env",
    "execute_run",
    "launch_run_background",
    "map_severity",
    "parse_run_metadata",
    "parse_vulnerabilities",
    "render_instruction_file",
    "resolve_model_profile",
    "stop_run_process",
    "enrich_cves",
    # brigade_handoff
    "BRIGADE_HANDOFF_AGENT",
    "BrigadeHandoffClient",
    "BrigadeHandoffPayload",
    "HandoffError",
    "HandoffNotConfigured",
    "build_handoff_payload",
    "default_client",
    "handoff_finding",
]
