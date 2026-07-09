"""app.engine.parsers.semgrep — Semgrep -> DojoFinding (native JSON or SARIF).

Semgrep (and its drop-in fork Opengrep — see ``opengrep.py``) can emit either its rich
native JSON (``{"results": [...]}`` with ``check_id`` / ``extra.metadata.cwe``) or
SARIF. This parser handles the native shape directly and delegates a SARIF document
(``{"runs": [...]}``) to :func:`app.engine.parsers.sarif.parse_sarif`, so a caller need
not know which ``--sarif``/``--json`` flag produced the report.
"""

from __future__ import annotations

from typing import Any

from app.engine.parsers.base import (
    DojoFinding,
    Parser,
    _first,
    _to_str,
    load_report,
)
from app.engine.parsers.sarif import _sarif_cwe, parse_sarif
from app.models.finding import FindingSeverity

# Semgrep's extra.severity is a lint level, not a risk rating.
_SEMGREP_SEVERITY: dict[str, FindingSeverity] = {
    "error": FindingSeverity.HIGH,
    "warning": FindingSeverity.MEDIUM,
    "info": FindingSeverity.LOW,
}


def dojo_from_semgrep(item: dict[str, Any], tool_name: str = "semgrep") -> DojoFinding:
    check_id = _to_str(_first(item, "check_id", "checkId"))
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    start = item.get("start") if isinstance(item.get("start"), dict) else {}

    title = (check_id.split(".")[-1] if check_id else None) or _to_str(extra.get("message")) or "Semgrep finding"
    file_path = _to_str(_first(item, "path", "file"))
    line = start.get("line") if isinstance(start.get("line"), int) else None
    endpoint = f"{file_path}:{line}" if file_path and line is not None else file_path

    level = (_to_str(extra.get("severity")) or "warning").lower()
    severity = _SEMGREP_SEVERITY.get(level, FindingSeverity.MEDIUM)
    # Semgrep metadata.cwe is usually "CWE-89: <name>" (a descriptive string) — extract
    # the bare identifier so it normalizes to a clean CWE-<n>.
    cwe = _sarif_cwe(metadata.get("cwe"))

    return DojoFinding(
        tool=tool_name,
        title=str(title),
        severity=severity,
        cwe=cwe,
        endpoint=endpoint,
        payload=None,
        poc=None,
        description=_to_str(extra.get("message")),
        file_path=file_path,
        line=line,
        references=metadata.get("references") or metadata.get("reference"),
        tags=metadata.get("owasp") or metadata.get("category"),
        vuln_id_from_tool=check_id,
        evidence_extra={
            "check_id": check_id,
            "severity_raw": _to_str(extra.get("severity")),
            "confidence": _to_str(metadata.get("confidence")),
            "fingerprint": _to_str(extra.get("fingerprint")),
        },
        raw=item,
    )


class SemgrepParser(Parser):
    tool = "semgrep"

    def parse_findings(self, report: dict | list | str | bytes) -> list[DojoFinding]:
        data = load_report(report)
        if isinstance(data, dict) and isinstance(data.get("runs"), list):
            return parse_sarif(data, tool_name=self.tool)
        results = data.get("results") if isinstance(data, dict) else data
        if not isinstance(results, list):
            return []
        return [dojo_from_semgrep(it, self.tool) for it in results if isinstance(it, dict)]
