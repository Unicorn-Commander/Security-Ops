"""app.engine.parsers.generic — DefectDojo "Generic Findings Import" -> DojoFinding.

The permissive fallback + the on-ramp for any tool that can be coaxed into a simple
JSON shape. Mirrors DefectDojo's "Generic Findings Import" contract: a top-level
``{"findings": [ {title, severity, description, mitigation, cwe, cve, cvssv3,
file_path, line, component_name, component_version, references, unique_id_from_tool,
vuln_id_from_tool, epss_score, endpoints, tags, ...} ]}`` (a bare top-level array is
also accepted). Every recognized key maps to its :class:`DojoFinding` slot; the whole
item is retained as ``raw`` so nothing is lost.

This is the "wire a CLI + point at a parser" escape hatch: a new scanner that can emit
this shape (or be shimmed into it) needs no bespoke parser at all — register nothing,
call ``get_parser("generic").parse(report)``.

NOTE: unlike the secret-bearing tool parsers, this does NOT redact — it faithfully
carries whatever the caller provides. Do not point it at raw secret-scanner output;
use the dedicated ``gitleaks`` / ``trivy`` parsers, which redact.
"""

from __future__ import annotations

from typing import Any

from app.engine.parsers.base import (
    DojoFinding,
    Parser,
    _first,
    _to_float,
    _to_str,
    load_report,
)


def dojo_from_generic(item: dict[str, Any]) -> DojoFinding:
    endpoints = item.get("endpoints")
    if isinstance(endpoints, str):
        endpoints = [endpoints]
    elif isinstance(endpoints, list):
        endpoints = [_to_str(e) for e in endpoints if e is not None]
    else:
        endpoints = None
    line = _first(item, "line", "line_number", "sast_source_line")
    return DojoFinding(
        tool="generic",
        title=_to_str(_first(item, "title", "name")) or "Finding",
        severity=_first(item, "severity", "sev"),
        cwe=_first(item, "cwe", "cwe_id"),
        endpoint=_to_str(_first(item, "endpoint", "url")),
        payload=_to_str(item.get("payload")),
        poc=_to_str(_first(item, "poc", "steps_to_reproduce")),
        description=_to_str(item.get("description")),
        mitigation=_to_str(_first(item, "mitigation", "remediation")),
        cve=_to_str(item.get("cve")),
        cvssv3=_to_str(item.get("cvssv3")),
        cvssv3_score=_to_float(_first(item, "cvssv3_score", "cvss")),
        epss_score=_to_float(item.get("epss_score")),
        epss_percentile=_to_float(item.get("epss_percentile")),
        file_path=_to_str(_first(item, "file_path", "file")),
        line=line if isinstance(line, int) else None,
        component_name=_to_str(item.get("component_name")),
        component_version=_to_str(item.get("component_version")),
        references=item.get("references") or item.get("url"),
        tags=item.get("tags"),
        unique_id_from_tool=_to_str(item.get("unique_id_from_tool")),
        vuln_id_from_tool=_to_str(item.get("vuln_id_from_tool")),
        endpoints=endpoints or None,
        raw=item,
    )


class GenericParser(Parser):
    tool = "generic"

    def parse_findings(self, report: dict | list | str | bytes) -> list[DojoFinding]:
        data = load_report(report)
        if isinstance(data, dict):
            data = data.get("findings")
        if not isinstance(data, list):
            return []
        return [dojo_from_generic(it) for it in data if isinstance(it, dict)]
