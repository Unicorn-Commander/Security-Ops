"""Nuclei JSONL parsing (engine #2) — the -jsonl → normalized-finding contract.

Pins the mapping from Nuclei's ``-jsonl`` output (one JSON object per line) onto the
shared :class:`ParsedVulnerability` shape that ``StrixRunner._store_findings`` writes,
using the field names a real ``nuclei`` run emits. Tolerant of blank/malformed lines.
"""

from __future__ import annotations

import json

from app.engine.nuclei_runner import _cwe_first, _parse_nuclei_jsonl, _vuln_from_nuclei
from app.models.finding import FindingSeverity

_ROWS = [
    {
        "template-id": "sqli-error-based",
        "info": {
            "name": "Error-Based SQL Injection",
            "severity": "high",
            "description": "Error-based SQLi in the q parameter.",
            "tags": ["sqli", "injection"],
            "reference": ["https://owasp.org/sqli"],
            "classification": {"cve-id": None, "cwe-id": ["CWE-89"]},
        },
        "type": "http",
        "host": "http://host.docker.internal:3000",
        "matched-at": "http://host.docker.internal:3000/rest/products/search?q=1",
        "extracted-results": ["SQLITE_ERROR"],
        "curl-command": "curl -X GET 'http://host.docker.internal:3000/rest/products/search?q=1'",
    },
    {
        "template-id": "apache-detect",
        "info": {"name": "Apache Detection", "severity": "info", "tags": ["tech"]},
        "type": "http",
        "matched-at": "http://host.docker.internal:3000",
    },
]


def _write_jsonl(tmp_path, rows):
    p = tmp_path / "nuclei.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return p


def test_parses_all_rows(tmp_path):
    _write_jsonl(tmp_path, _ROWS)
    findings = _parse_nuclei_jsonl(tmp_path / "nuclei.jsonl")
    assert len(findings) == 2


def test_maps_severity_endpoint_cwe_payload(tmp_path):
    f = _vuln_from_nuclei(_ROWS[0])
    assert f.title == "Error-Based SQL Injection"
    assert f.severity == FindingSeverity.HIGH
    assert f.endpoint == "http://host.docker.internal:3000/rest/products/search?q=1"
    assert f.cwe == "CWE-89"  # list -> first, normalized
    assert f.payload.startswith("curl -X GET")
    assert f.evidence["template_id"] == "sqli-error-based"
    assert f.evidence["engine"] == "nuclei"


def test_falls_back_to_template_id_and_info_severity(tmp_path):
    f = _vuln_from_nuclei(_ROWS[1])
    assert f.title == "Apache Detection"
    assert f.severity == FindingSeverity.INFO
    assert f.endpoint == "http://host.docker.internal:3000"
    assert f.cwe is None


def test_tolerates_blank_and_malformed_lines(tmp_path):
    p = tmp_path / "nuclei.jsonl"
    p.write_text(
        json.dumps(_ROWS[0]) + "\n\n" + "{not valid json\n" + json.dumps(_ROWS[1]) + "\n",
        encoding="utf-8",
    )
    findings = _parse_nuclei_jsonl(p)
    assert len(findings) == 2  # blank + malformed skipped, both valid rows kept


def test_missing_file_is_empty(tmp_path):
    assert _parse_nuclei_jsonl(tmp_path / "nope.jsonl") == []


def test_cwe_first_handles_list_and_scalar():
    assert _cwe_first(["CWE-89", "CWE-90"]) == "CWE-89"
    assert _cwe_first("CWE-200") == "CWE-200"
    assert _cwe_first([]) is None
    assert _cwe_first(None) is None
