"""app.engine.parsers.sarif — SARIF 2.1.0 -> DojoFinding.

SARIF (OASIS Static Analysis Results Interchange Format) is the common denominator for
a whole class of scanners — Opengrep/Semgrep, ZAP, CodeQL, and many linters all emit
it — so a single parser here lets any SARIF-capable engine wire in with zero bespoke
mapping. Walks ``runs[].results[]``, resolving each result's rule metadata (cwe, tags,
help/uri, ``security-severity``) from the run's ``tool.driver.rules[]`` by ``ruleId`` /
``ruleIndex`` and merging any inline ``result.properties``.

Severity: a numeric ``security-severity`` (a CVSS-like 0-10, the SARIF convention many
tools use) wins and is banded to CRITICAL/HIGH/MEDIUM/LOW/INFO; otherwise the SARIF
``level`` (error/warning/note/none) is mapped. The raw level + score are retained in
evidence.
"""

from __future__ import annotations

import re
from typing import Any

from app.engine.parsers.base import (
    DojoFinding,
    Parser,
    _to_float,
    _to_str,
    load_report,
)
from app.models.finding import FindingSeverity

# SARIF result.level -> our severity (used when there is no numeric security-severity).
_LEVEL_SEVERITY: dict[str, FindingSeverity] = {
    "error": FindingSeverity.HIGH,
    "warning": FindingSeverity.MEDIUM,
    "note": FindingSeverity.INFO,
    "none": FindingSeverity.INFO,
}

_CWE_RE = re.compile(r"cwe[-_ ]?(\d+)", re.IGNORECASE)


def _severity_from_score(score: float) -> FindingSeverity:
    """Band a CVSS-like 0-10 ``security-severity`` (the NVD/SARIF convention)."""
    if score >= 9.0:
        return FindingSeverity.CRITICAL
    if score >= 7.0:
        return FindingSeverity.HIGH
    if score >= 4.0:
        return FindingSeverity.MEDIUM
    if score > 0.0:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def _sarif_cwe(*sources: Any) -> str | None:
    """Extract the first ``CWE-<n>`` from any of the given properties values.

    SARIF tools carry CWEs inconsistently — a ``cwe`` property list (``["CWE-79"]`` or
    ``["external/cwe/cwe-79"]``), a ``tags`` list, or a bare string — so scan them all
    for the first ``cwe-<digits>`` token.
    """
    for src in sources:
        values = src if isinstance(src, (list, tuple)) else [src]
        for value in values:
            if value is None:
                continue
            m = _CWE_RE.search(str(value))
            if m:
                return f"CWE-{int(m.group(1))}"
    return None


def _first_location(result: dict[str, Any]) -> tuple[str | None, int | None]:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None, None
    phys = locations[0].get("physicalLocation") if isinstance(locations[0], dict) else None
    if not isinstance(phys, dict):
        return None, None
    art = phys.get("artifactLocation") if isinstance(phys.get("artifactLocation"), dict) else {}
    region = phys.get("region") if isinstance(phys.get("region"), dict) else {}
    uri = _to_str(art.get("uri"))
    line = region.get("startLine")
    return uri, line if isinstance(line, int) else None


def _rule_index(driver: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
    index: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if isinstance(rule, dict) and rule.get("id") is not None:
            index[str(rule["id"])] = rule
    return index


def _rule_for(result: dict[str, Any], driver: dict[str, Any], rules: list) -> dict[str, Any]:
    rule_id = result.get("ruleId")
    if rule_id is not None:
        by_id = _rule_index(driver).get(str(rule_id))
        if by_id is not None:
            return by_id
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules) and isinstance(rules[idx], dict):
        return rules[idx]
    return {}


def dojo_from_sarif_result(
    result: dict[str, Any], driver: dict[str, Any], tool_name: str
) -> DojoFinding:
    rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
    rule = _rule_for(result, driver, rules)
    rule_props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    res_props = result.get("properties") if isinstance(result.get("properties"), dict) else {}

    rule_id = _to_str(result.get("ruleId")) or _to_str(rule.get("id"))
    short_desc = rule.get("shortDescription") if isinstance(rule.get("shortDescription"), dict) else {}
    message = result.get("message") if isinstance(result.get("message"), dict) else {}
    msg_text = _to_str(message.get("text"))
    title = _to_str(rule.get("name")) or _to_str(short_desc.get("text")) or rule_id or "SARIF finding"

    file_path, line = _first_location(result)
    endpoint = f"{file_path}:{line}" if file_path and line is not None else file_path

    score = _to_float(res_props.get("security-severity") or rule_props.get("security-severity"))
    if score is not None:
        severity: str | FindingSeverity = _severity_from_score(score)
    else:
        level = _to_str(result.get("level")) or _to_str(rule.get("defaultLevel")) or "warning"
        severity = _LEVEL_SEVERITY.get(level.lower(), FindingSeverity.MEDIUM)

    help_uri = _to_str(rule.get("helpUri"))
    full_desc = rule.get("fullDescription") if isinstance(rule.get("fullDescription"), dict) else {}
    description = msg_text or _to_str(full_desc.get("text")) or _to_str(short_desc.get("text"))

    return DojoFinding(
        tool=tool_name,
        title=str(title),
        severity=severity,
        cwe=_sarif_cwe(rule_props.get("cwe"), res_props.get("cwe"), rule_props.get("tags")),
        endpoint=endpoint,
        payload=None,
        poc=help_uri,
        description=description,
        file_path=file_path,
        line=line,
        references=help_uri,
        tags=rule_props.get("tags"),
        vuln_id_from_tool=rule_id,
        unique_id_from_tool=_to_str(result.get("guid")),
        evidence_extra={
            "level": _to_str(result.get("level")),
            "security_severity": score,
            "rule_id": rule_id,
        },
        raw=result,
    )


def parse_sarif(report: Any, *, tool_name: str = "sarif") -> list[DojoFinding]:
    """Parse a SARIF document into intermediate findings (shared by tool parsers)."""
    data = load_report(report)
    if not isinstance(data, dict):
        return []
    runs = data.get("runs")
    if not isinstance(runs, list):
        return []
    out: list[DojoFinding] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
        driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
        run_tool = _to_str(driver.get("name")) or tool_name
        label = tool_name if tool_name != "sarif" else (run_tool.lower() if run_tool else "sarif")
        for result in run.get("results") or []:
            if isinstance(result, dict):
                out.append(dojo_from_sarif_result(result, driver, label))
    return out


class SarifParser(Parser):
    """Generic SARIF 2.1.0 parser (engine label taken from the SARIF tool name)."""

    tool = "sarif"

    def parse_findings(self, report: dict | list | str | bytes) -> list[DojoFinding]:
        return parse_sarif(report, tool_name=self.tool)
