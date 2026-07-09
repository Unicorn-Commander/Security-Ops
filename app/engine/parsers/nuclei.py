"""app.engine.parsers.nuclei — Nuclei ``-jsonl`` -> DojoFinding.

Re-expresses the field map proven in ``nuclei_runner._vuln_from_nuclei`` on the
DefectDojo intermediate so ``get_parser("nuclei").parse(report)`` emits a
``list[ParsedVulnerability]`` identical to the runner's hand-rolled parser (pinned by
``tests/test_parsers_defectdojo.py``). Input may be Nuclei's raw JSONL text (one JSON
object per line) or an already-decoded list of row dicts.
"""

from __future__ import annotations

from typing import Any

from app.engine.parsers.base import (
    DojoFinding,
    Parser,
    _first,
    _to_str,
    first_scalar,
    iter_jsonl,
)


def dojo_from_nuclei(item: dict[str, Any]) -> DojoFinding:
    """Map one Nuclei result object onto a :class:`DojoFinding`."""
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    classification = (
        info.get("classification") if isinstance(info.get("classification"), dict) else {}
    )
    template_id = _first(item, "template-id", "templateID", "template")
    title = _to_str(_first(info, "name", default=None)) or (
        str(template_id) if template_id else "Nuclei finding"
    )
    references = info.get("reference") or info.get("references")
    return DojoFinding(
        tool="nuclei",
        title=str(title),
        severity=info.get("severity"),
        cwe=first_scalar(classification.get("cwe-id") or classification.get("cwe_id")),
        endpoint=_to_str(_first(item, "matched-at", "matched_at", "host", "url")),
        payload=_to_str(_first(item, "curl-command", "curl_command", "request")),
        poc=_to_str(_first(item, "matched-at", "matched_at")),
        description=_to_str(info.get("description")),
        references=references,
        cve=first_scalar(classification.get("cve-id") or classification.get("cve_id")),
        tags=info.get("tags"),
        evidence_extra={
            "template_id": str(template_id) if template_id else None,
            "extracted": item.get("extracted-results") or item.get("extracted_results"),
        },
        raw=item,
    )


class NucleiParser(Parser):
    tool = "nuclei"

    def parse_findings(self, report: dict | list | str | bytes) -> list[DojoFinding]:
        return [dojo_from_nuclei(item) for item in iter_jsonl(report)]
