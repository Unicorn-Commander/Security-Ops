"""app.reports.builder — the pure engagement-report assembler (spec §8).

Turns already-loaded rows (an :class:`~app.models.engagement.Engagement`, its
:class:`~app.models.run.Run`\\ s, and the :class:`~app.models.finding.Finding`\\ s
grouped by run) into a single branded Markdown document. The document has three
parts:

1. a **branded header** (``config.report_brand_name`` + tagline + the engagement
   name/id + an injected ``generated_at`` timestamp),
2. an **executive summary** (severity histogram, run/finding counts, the highest
   severity observed), and
3. a **per-finding section** (title, severity, CWE, endpoint, PoC, remediation
   pulled from ``evidence["remediation"]``, and an evidence summary),

with Strix's own ``penetration_test_report.md`` — the frontier-verified,
client-facing pass (spec §8) — appended verbatim under a "Full engine report"
heading when supplied.

**Purity contract:** :func:`build_engagement_report` and its helpers do NO I/O and
NEVER read the clock — the caller injects ``generated_at`` (the service supplies
``datetime.now(timezone.utc)``). This keeps the whole assembler deterministic and
unit-testable. The one function that touches the filesystem,
:func:`read_strix_report`, is kept deliberately separate.

Dependency direction (no cycles): reports -> {core.config, models}. Nothing here
imports services/api.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from app.core.config import Settings, settings
from app.models.finding import FindingSeverity

if TYPE_CHECKING:  # typing only — no runtime coupling / cycle
    from app.models.engagement import Engagement
    from app.models.finding import Finding
    from app.models.run import Run

log = logging.getLogger("secops.reports.builder")

# Severity ordering, most-severe first — drives the summary histogram order and the
# "highest severity observed" computation. Higher rank == more severe.
_SEVERITY_ORDER: list[FindingSeverity] = [
    FindingSeverity.CRITICAL,
    FindingSeverity.HIGH,
    FindingSeverity.MEDIUM,
    FindingSeverity.LOW,
    FindingSeverity.INFO,
]
_SEVERITY_RANK: dict[FindingSeverity, int] = {
    sev: rank for rank, sev in enumerate(reversed(_SEVERITY_ORDER))
}


def _sev(finding: "Finding") -> FindingSeverity:
    """The finding's severity as a :class:`FindingSeverity` (tolerant of a raw str)."""
    value = finding.severity
    if isinstance(value, FindingSeverity):
        return value
    try:
        return FindingSeverity(str(value).strip().upper())
    except ValueError:  # pragma: no cover - defensive; runner always maps to the enum
        return FindingSeverity.MEDIUM


def _enum_value(value: Any) -> str:
    """Render an enum (or plain value) as its string, e.g. ``RunStatus.COMPLETED`` -> ``COMPLETED``."""
    return str(getattr(value, "value", value))


def read_strix_report(run: "Run") -> str | None:
    """Read the Strix ``penetration_test_report.md`` for a run from disk, or ``None``.

    The runner stores the report path on ``run.report_path`` at the run's terminal
    transition. Returns the file's text when the path is set and the file exists;
    returns ``None`` (never raises) when unset, missing, or unreadable. This is the
    ONLY I/O in this module and is intentionally isolated from the pure builder so
    callers can unit-test :func:`build_engagement_report` with an in-memory string.
    """
    path = getattr(run, "report_path", None)
    if not path:
        return None
    try:
        file = Path(path)
        if not file.exists():
            return None
        return file.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - defensive I/O guard
        log.warning("reports.read_strix_report failed for %s: %s", path, exc)
        return None


def build_engagement_report(
    engagement: "Engagement",
    runs: Sequence["Run"],
    findings_by_run: Mapping[uuid.UUID, Sequence["Finding"]],
    *,
    generated_at: datetime,
    strix_report_text: str | None = None,
    config: Settings | None = None,
) -> str:
    """Assemble the branded Markdown engagement report (pure — no I/O, no clock).

    ``findings_by_run`` maps a run id to that run's findings; runs with no findings
    may be omitted from the mapping. ``generated_at`` is injected by the caller (the
    service passes ``datetime.now(timezone.utc)``) — this function never calls the
    clock. ``strix_report_text`` is the trustworthy client-facing engine report
    (spec §8) appended verbatim under a "Full engine report" heading when present.
    """
    cfg = config or settings
    brand = cfg.report_brand_name
    tagline = cfg.report_brand_tagline

    all_findings: list["Finding"] = [
        f for run in runs for f in findings_by_run.get(run.id, [])
    ]
    # Include any findings whose run is not in `runs` (defensive: keep counts honest).
    seen_runs = {run.id for run in runs}
    for run_id, findings in findings_by_run.items():
        if run_id not in seen_runs:
            all_findings.extend(findings)

    counts = _severity_counts(all_findings)
    highest = _highest_severity(all_findings)

    lines: list[str] = []
    lines += _render_header(engagement, brand, tagline, generated_at)
    lines += _render_summary(engagement, runs, all_findings, counts, highest)
    lines += _render_findings(runs, findings_by_run)
    lines += _render_full_engine_report(strix_report_text, brand)

    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Section renderers (pure)
# ---------------------------------------------------------------------------
def _render_header(
    engagement: "Engagement", brand: str, tagline: str, generated_at: datetime
) -> list[str]:
    return [
        f"# {brand} — Engagement Report",
        "",
        f"*{tagline}*",
        "",
        f"- **Engagement:** {getattr(engagement, 'name', 'engagement')}",
        f"- **Engagement ID:** {getattr(engagement, 'id', '')}",
        f"- **Status:** {_enum_value(getattr(engagement, 'status', ''))}",
        f"- **Generated:** {generated_at.isoformat()}",
        "",
        "---",
        "",
    ]


def _render_summary(
    engagement: "Engagement",
    runs: Sequence["Run"],
    all_findings: Sequence["Finding"],
    counts: dict[FindingSeverity, int],
    highest: FindingSeverity | None,
) -> list[str]:
    lines = [
        "## Executive summary",
        "",
        f"- **Runs:** {len(runs)}",
        f"- **Findings:** {len(all_findings)}",
        f"- **Highest severity:** {highest.value if highest else 'None'}",
        "",
    ]
    if not all_findings:
        lines += [
            "No findings were recorded for this engagement.",
            "",
        ]
        return lines
    lines += ["| Severity | Count |", "| --- | --- |"]
    lines += [f"| {sev.value} | {counts.get(sev, 0)} |" for sev in _SEVERITY_ORDER]
    lines += [""]
    return lines


def _render_findings(
    runs: Sequence["Run"],
    findings_by_run: Mapping[uuid.UUID, Sequence["Finding"]],
) -> list[str]:
    lines = ["## Findings", ""]
    total = sum(len(findings_by_run.get(run.id, [])) for run in runs)
    # Also account for orphan findings whose run isn't in `runs`.
    seen_runs = {run.id for run in runs}
    orphans = {
        rid: fs for rid, fs in findings_by_run.items() if rid not in seen_runs
    }
    total += sum(len(fs) for fs in orphans.values())

    if total == 0:
        lines += ["No findings to report.", ""]
        return lines

    for run in runs:
        run_findings = list(findings_by_run.get(run.id, []))
        if not run_findings:
            continue
        lines += _render_run_group(run, run_findings)

    for rid, run_findings in orphans.items():
        lines += [f"### Run `{rid}`", ""]
        for finding in run_findings:
            lines += _render_finding(finding)
    return lines


def _render_run_group(run: "Run", run_findings: Sequence["Finding"]) -> list[str]:
    header = (
        f"### Run `{run.id}` — {_enum_value(getattr(run, 'mode', ''))} / "
        f"{_enum_value(getattr(run, 'status', ''))}"
    )
    lines = [header, ""]
    for finding in run_findings:
        lines += _render_finding(finding)
    return lines


def _render_finding(finding: "Finding") -> list[str]:
    sev = _sev(finding)
    evidence: dict[str, Any] = finding.evidence or {}
    lines = [
        f"#### {finding.title}  ·  {sev.value}",
        "",
    ]
    meta: list[str] = []
    if finding.cwe:
        meta.append(f"- **CWE:** {finding.cwe}")
    if finding.endpoint:
        meta.append(f"- **Endpoint:** {finding.endpoint}")
    status = getattr(finding, "status", None)
    if status is not None:
        meta.append(f"- **Status:** {_enum_value(status)}")
    if finding.verified_by:
        meta.append(f"- **Verified by:** {finding.verified_by}")
    if meta:
        lines += meta + [""]

    description = evidence.get("description")
    if description:
        lines += ["**Summary**", "", str(description).strip(), ""]

    if finding.poc:
        lines += ["**Proof of concept**", "", "```", str(finding.poc).strip(), "```", ""]

    remediation = evidence.get("remediation")
    if remediation:
        lines += ["**Remediation**", "", str(remediation).strip(), ""]

    evidence_summary = _render_evidence(evidence)
    if evidence_summary:
        lines += ["**Evidence**", "", *evidence_summary, ""]

    return lines


def _render_evidence(evidence: Mapping[str, Any]) -> list[str]:
    """A compact bullet list of the human-relevant evidence keys (skips raw/dupes)."""
    skip = {"raw", "description", "remediation"}
    bullets: list[str] = []
    for key, value in evidence.items():
        if key in skip or value in (None, "", [], {}):
            continue
        bullets.append(f"- **{key}:** {_scalarize(value)}")
    return bullets


def _scalarize(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _render_full_engine_report(strix_report_text: str | None, brand: str) -> list[str]:
    if not strix_report_text or not strix_report_text.strip():
        return []
    return [
        "---",
        "",
        "## Full engine report",
        "",
        f"*The following is the engine's frontier-verified penetration-test report, "
        f"reproduced verbatim below the {brand} summary above.*",
        "",
        strix_report_text.strip(),
        "",
    ]


# ---------------------------------------------------------------------------
# Aggregation helpers (pure)
# ---------------------------------------------------------------------------
def _severity_counts(findings: Sequence["Finding"]) -> dict[FindingSeverity, int]:
    counts: dict[FindingSeverity, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    for finding in findings:
        counts[_sev(finding)] = counts.get(_sev(finding), 0) + 1
    return counts


def _highest_severity(findings: Sequence["Finding"]) -> FindingSeverity | None:
    if not findings:
        return None
    return max((_sev(f) for f in findings), key=lambda s: _SEVERITY_RANK[s])


__all__ = ["build_engagement_report", "read_strix_report"]
