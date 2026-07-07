"""Gitleaks JSON parsing (engine #3) — the report → normalized-finding contract.

Pins the mapping from gitleaks' JSON report (a top-level array of leak objects) onto
the shared :class:`ParsedVulnerability` shape that ``StrixRunner._store_findings``
writes, using the field names a real ``gitleaks detect --report-format json`` run
emits. Tolerant of blank/malformed reports and missing files.

CRITICAL: the plaintext secret must NEVER appear in a parsed finding (title,
endpoint, payload, poc, evidence, or raw). ``test_plaintext_secret_never_stored``
asserts that invariant — this platform must never become a secret-exfil vector.
"""

from __future__ import annotations

import json

from app.engine.gitleaks_runner import (
    _parse_gitleaks_json,
    _redact_secret,
    _sanitize_gitleaks_item,
    _vuln_from_gitleaks,
)
from app.models.finding import FindingSeverity

# A real plaintext secret used across the redaction assertions.
_PLAINTEXT = "AKIAIOSFODNN7EXAMPLE1234"

_ROWS = [
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key",
        "StartLine": 12,
        "EndLine": 12,
        "StartColumn": 5,
        "EndColumn": 40,
        "Match": f"aws_key = {_PLAINTEXT}",
        "Secret": _PLAINTEXT,
        "File": "config/prod.yaml",
        "Commit": "9f2c1ab7c0de1234567890abcdef1234567890ab",
        "Author": "Jane Dev",
        "Email": "demo@example.invalid",
        "Date": "2026-01-02T03:04:05Z",
        "Tags": ["key", "AWS"],
        "Fingerprint": "config/prod.yaml:aws-access-token:12",
    },
    {
        "RuleID": "generic-api-key",
        "Description": "",  # falls back to RuleID
        "StartLine": 3,
        "Secret": "REMOVED",
        "Match": "token: REMOVED",
        "File": "src/app.py",
        "Fingerprint": "src/app.py:generic-api-key:3",
    },
]


def _write_json(tmp_path, rows, name="gitleaks.0.json"):
    p = tmp_path / name
    p.write_text(json.dumps(rows), encoding="utf-8")
    return p


def test_parses_all_rows(tmp_path):
    p = _write_json(tmp_path, _ROWS)
    findings = _parse_gitleaks_json(p)
    assert len(findings) == 2


def test_maps_title_severity_endpoint_cwe(tmp_path):
    f = _vuln_from_gitleaks(_ROWS[0])
    assert f.title == "AWS Access Key"
    assert f.severity == FindingSeverity.HIGH  # secrets are HIGH by default
    assert f.endpoint == "config/prod.yaml:12"
    assert f.cwe == "CWE-798"  # hard-coded credentials
    assert f.evidence["engine"] == "gitleaks"
    assert f.evidence["rule_id"] == "aws-access-token"
    assert f.evidence["commit"] == "9f2c1ab7c0de1234567890abcdef1234567890ab"
    # The location fingerprint (safe) is retained; used as the PoC reference.
    assert f.poc == "config/prod.yaml:aws-access-token:12"


def test_falls_back_to_rule_id_when_no_description(tmp_path):
    f = _vuln_from_gitleaks(_ROWS[1])
    assert f.title == "generic-api-key"
    assert f.endpoint == "src/app.py:3"


def test_plaintext_secret_never_stored(tmp_path):
    """The redaction invariant: no plaintext secret anywhere in a parsed finding."""
    for row in _ROWS:
        f = _vuln_from_gitleaks(row)
        blob = json.dumps(
            {
                "title": f.title,
                "endpoint": f.endpoint,
                "payload": f.payload,
                "poc": f.poc,
                "cwe": f.cwe,
                "evidence": f.evidence,
                "raw": f.raw,
            },
            default=str,
        )
        assert row["Secret"] not in blob, "plaintext Secret leaked into finding"
        assert row["Match"] not in blob, "raw Match leaked into finding"
        # payload must never carry the match/secret.
        assert f.payload is None
        # A redacted fingerprint IS present (proves we saw the secret, redacted it).
        assert f.evidence.get("secret_fingerprint")
        assert row["Secret"] not in f.evidence["secret_fingerprint"]


def test_redact_secret_is_non_reversible():
    fp = _redact_secret(_PLAINTEXT)
    assert fp == "AKIA…(len=24)"
    assert _PLAINTEXT not in fp
    assert _redact_secret("") is None
    assert _redact_secret(None) is None


def test_sanitize_drops_secret_fields():
    clean = _sanitize_gitleaks_item(_ROWS[0])
    assert "Secret" not in clean
    assert "Match" not in clean
    # Non-secret metadata is preserved.
    assert clean["RuleID"] == "aws-access-token"
    assert clean["File"] == "config/prod.yaml"


def test_tolerates_blank_and_malformed_reports(tmp_path):
    assert _parse_gitleaks_json(tmp_path / "nope.json") == []  # missing
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    assert _parse_gitleaks_json(empty) == []  # blank (clean repo)
    clean = tmp_path / "clean.json"
    clean.write_text("[]", encoding="utf-8")
    assert _parse_gitleaks_json(clean) == []  # explicit empty array
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    assert _parse_gitleaks_json(bad) == []  # malformed -> skipped, not raised
