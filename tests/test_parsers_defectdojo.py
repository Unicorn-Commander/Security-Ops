"""DefectDojo-style unified parser adapter — registry, base mapper, redaction, and
equivalence with the hand-rolled runners.

Covers the new ``app.engine.parsers`` package (the tool-agnostic normalization layer):

* the registry (``get_parser`` / ``PARSERS`` — aliases, case, unknown -> None),
* the :class:`DojoFinding` -> :class:`ParsedVulnerability` mapper (evidence funnel +
  None-filter, severity/CWE normalization semantics that match ``strix_runner``),
* the CRITICAL redaction invariant for the secret-bearing tools (gitleaks +
  trivy-secrets) driven THROUGH the parser path — plaintext must never survive,
* per-tool fixtures for nuclei / trivy / gitleaks / sarif / semgrep / opengrep / zap /
  generic,
* and — the load-bearing guarantee for the runner-migration path —
  ``test_equivalence_*`` proving the parser emits a ``list[ParsedVulnerability]``
  IDENTICAL to the existing runner's ``_parse_*`` for nuclei, trivy, and gitleaks.
"""

from __future__ import annotations

import json

from app.engine.gitleaks_runner import _vuln_from_gitleaks
from app.engine.nuclei_runner import _vuln_from_nuclei
from app.engine.parsers import PARSERS, get_parser
from app.engine.parsers.base import (
    DojoFinding,
    Parser,
    normalize_cwe,
    normalize_severity,
)
from app.engine.parsers.generic import GenericParser
from app.engine.parsers.gitleaks import GitleaksParser
from app.engine.parsers.nuclei import NucleiParser
from app.engine.parsers.opengrep import OpengrepParser
from app.engine.parsers.trivy import TrivyParser
from app.engine.parsers.zap import ZapParser
from app.engine.strix_runner import ParsedVulnerability
from app.engine.trivy_runner import _parse_trivy_json
from app.models.finding import FindingSeverity

# A real plaintext secret reused across the redaction assertions.
_PLAINTEXT = "AKIAIOSFODNN7EXAMPLE1234"

# --- Fixtures mirroring what the real tools emit ---------------------------
# Nuclei -jsonl rows (same shape as tests/test_nuclei_parse.py).
_NUCLEI_ROWS = [
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

# Trivy report (same shape as tests/test_trivy_parse.py) — includes a plaintext secret.
_TRIVY_REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": "nginx:1.21",
    "Results": [
        {
            "Target": "nginx:1.21 (debian 11.2)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-3711",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1k-1",
                    "FixedVersion": "1.1.1l-1",
                    "Severity": "CRITICAL",
                    "Title": "openssl: SM2 Decryption Buffer Overflow",
                    "Description": "A flaw in OpenSSL SM2 decryption.",
                    "CweIDs": ["CWE-787"],
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3711"],
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-3711",
                }
            ],
        },
        {
            "Target": "Dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Severity": "HIGH",
                    "Message": "Specify at least 1 USER command.",
                    "Resolution": "Add a USER command.",
                    "References": ["https://avd.aquasec.com/misconfig/ds002"],
                }
            ],
        },
        {
            "Target": "app/secrets.env",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key ID",
                    "StartLine": 4,
                    "Match": f"AWS_KEY={_PLAINTEXT}",
                    "Code": {"Lines": [{"Number": 4, "Content": f"AWS_KEY={_PLAINTEXT}"}]},
                }
            ],
        },
    ],
}

# Gitleaks report (same shape as tests/test_gitleaks_parse.py) — plaintext secrets.
_GITLEAKS_ROWS = [
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key",
        "StartLine": 12,
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


# ===========================================================================
# Registry
# ===========================================================================
def test_registry_known_tools_return_parser_instances():
    assert isinstance(get_parser("nuclei"), NucleiParser)
    assert isinstance(get_parser("trivy"), TrivyParser)
    assert isinstance(get_parser("gitleaks"), GitleaksParser)
    assert isinstance(get_parser("generic"), GenericParser)
    assert isinstance(get_parser("zap"), ZapParser)
    assert isinstance(get_parser("opengrep"), OpengrepParser)
    for parser in PARSERS.values():
        assert isinstance(parser, Parser)


def test_registry_case_insensitive_and_aliases():
    assert type(get_parser("NUCLEI")) is type(get_parser("nuclei"))
    assert type(get_parser("  Trivy  ")) is type(get_parser("trivy"))
    # trivy-secrets rides the same trivy report parser.
    assert isinstance(get_parser("trivy-secrets"), TrivyParser)
    assert isinstance(get_parser("owasp-zap"), ZapParser)


def test_registry_unknown_returns_none():
    assert get_parser("does-not-exist") is None
    assert get_parser("") is None


# ===========================================================================
# Base mapper — DojoFinding -> ParsedVulnerability
# ===========================================================================
def test_normalize_severity_matches_strix_semantics():
    # Unknown / missing -> MEDIUM (surfaces for review, not hidden as INFO).
    assert normalize_severity("nonsense") is FindingSeverity.MEDIUM
    assert normalize_severity(None) is FindingSeverity.MEDIUM
    assert normalize_severity("critical") is FindingSeverity.CRITICAL
    assert normalize_severity("Moderate") is FindingSeverity.MEDIUM
    # A pre-resolved enum passes straight through.
    assert normalize_severity(FindingSeverity.LOW) is FindingSeverity.LOW


def test_normalize_cwe_produces_prefixed_form():
    assert normalize_cwe(89) == "CWE-89"
    assert normalize_cwe("798") == "CWE-798"
    assert normalize_cwe("CWE-79") == "CWE-79"
    assert normalize_cwe(None) is None


def test_mapper_funnels_extra_into_evidence_and_drops_none():
    dojo = DojoFinding(
        tool="demo",
        title="Example",
        severity="high",
        cwe=89,
        endpoint="https://x/a",
        payload="p",
        poc="c",
        description="desc",
        mitigation="fix it",
        cve="CVE-2024-1",
        cvssv3_score=7.5,
        file_path="a.py",
        line=10,
        component_name="lib",
        component_version="1.0",
        references=["https://ref"],
        tags=["t"],
        evidence_extra={"custom": "kept", "blank": None},
        raw={"native": True},
    )
    pv = dojo.to_parsed_vulnerability()
    assert isinstance(pv, ParsedVulnerability)
    assert pv.title == "Example"
    assert pv.severity is FindingSeverity.HIGH
    assert pv.cwe == "CWE-89"
    assert pv.endpoint == "https://x/a"
    ev = pv.evidence
    assert ev["engine"] == "demo"
    # Everything without a first-class PV home is funneled in.
    assert ev["description"] == "desc"
    assert ev["mitigation"] == "fix it"
    assert ev["cve"] == "CVE-2024-1"
    assert ev["cvssv3_score"] == 7.5
    assert ev["file"] == "a.py"
    assert ev["line"] == 10
    assert ev["component_name"] == "lib"
    assert ev["custom"] == "kept"
    assert ev["raw"] == {"native": True}
    # None values are dropped (raw is always kept); PV core fields never leak in.
    assert "blank" not in ev
    assert "epss_score" not in ev


def test_mapper_backfills_endpoint_from_endpoints_list():
    dojo = DojoFinding(tool="demo", title="t", endpoints=["https://a", "https://b"])
    pv = dojo.to_parsed_vulnerability()
    assert pv.endpoint == "https://a"  # first endpoint backfills the scalar
    assert pv.evidence["endpoints"] == ["https://a", "https://b"]


def test_parser_stamps_tool_label_when_missing():
    class _Bare(Parser):
        tool = "bare"

        def parse_findings(self, report):
            return [DojoFinding(title="x")]  # tool left blank

    pv = _Bare().parse({})[0]
    assert pv.evidence["engine"] == "bare"


# ===========================================================================
# Per-tool fixtures
# ===========================================================================
def test_nuclei_parser_maps_fields():
    findings = get_parser("nuclei").parse(_NUCLEI_ROWS)
    assert len(findings) == 2
    f = findings[0]
    assert f.title == "Error-Based SQL Injection"
    assert f.severity is FindingSeverity.HIGH
    assert f.cwe == "CWE-89"
    assert f.endpoint == "http://host.docker.internal:3000/rest/products/search?q=1"
    assert f.payload.startswith("curl -X GET")
    assert f.evidence["engine"] == "nuclei"
    assert f.evidence["template_id"] == "sqli-error-based"


def test_nuclei_parser_accepts_jsonl_string():
    jsonl = "\n".join(json.dumps(r) for r in _NUCLEI_ROWS) + "\n"
    findings = get_parser("nuclei").parse(jsonl)
    assert [f.title for f in findings] == ["Error-Based SQL Injection", "Apache Detection"]


def test_nuclei_parser_tolerates_blank_and_malformed_jsonl():
    jsonl = json.dumps(_NUCLEI_ROWS[0]) + "\n\n{bad json\n" + json.dumps(_NUCLEI_ROWS[1]) + "\n"
    assert len(get_parser("nuclei").parse(jsonl)) == 2


def test_trivy_parser_maps_vuln_misconfig_secret():
    findings = get_parser("trivy").parse(_TRIVY_REPORT)
    assert len(findings) == 3
    vuln = findings[0]
    assert vuln.title == "CVE-2021-3711: openssl: SM2 Decryption Buffer Overflow"
    assert vuln.severity is FindingSeverity.CRITICAL
    assert vuln.cwe == "CWE-787"
    assert vuln.endpoint == "openssl@1.1.1k-1"
    assert vuln.payload == "Upgrade openssl to 1.1.1l-1"
    misconf = [f for f in findings if f.evidence.get("type") == "misconfig"][0]
    assert misconf.title == "DS002: Image user should not be 'root'"
    assert misconf.cwe is None


def test_generic_parser_maps_defectdojo_import_shape():
    report = {
        "findings": [
            {
                "title": "Hardcoded weak cipher",
                "severity": "High",
                "cwe": 327,
                "description": "DES in use",
                "mitigation": "Use AES-GCM",
                "file_path": "crypto.py",
                "line": 42,
                "cvssv3_score": 7.4,
                "epss_score": 0.12,
                "component_name": "pycrypto",
                "component_version": "2.6.1",
                "references": ["https://cwe.mitre.org/data/definitions/327.html"],
                "endpoints": ["https://svc/login"],
                "tags": ["crypto"],
            }
        ]
    }
    f = get_parser("generic").parse(report)[0]
    assert f.title == "Hardcoded weak cipher"
    assert f.severity is FindingSeverity.HIGH
    assert f.cwe == "CWE-327"
    assert f.endpoint == "https://svc/login"
    assert f.evidence["mitigation"] == "Use AES-GCM"
    assert f.evidence["file"] == "crypto.py"
    assert f.evidence["component_version"] == "2.6.1"
    assert f.evidence["epss_score"] == 0.12
    # A bare top-level array is also accepted.
    assert len(get_parser("generic").parse(report["findings"])) == 1


def test_sarif_parser_maps_semgrep_style_document():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Opengrep",
                        "rules": [
                            {
                                "id": "python.sqli",
                                "name": "SQL Injection",
                                "shortDescription": {"text": "SQLi"},
                                "helpUri": "https://ex/sqli",
                                "properties": {
                                    "cwe": ["CWE-89: SQL Injection"],
                                    "tags": ["security", "owasp-a03"],
                                    "security-severity": "8.5",
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "python.sqli",
                        "level": "error",
                        "message": {"text": "user input reaches a SQL sink"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/db.py"},
                                    "region": {"startLine": 21},
                                }
                            }
                        ],
                        "guid": "abc-123",
                    }
                ],
            }
        ],
    }
    f = get_parser("sarif").parse(sarif)[0]
    assert f.title == "SQL Injection"
    # Numeric security-severity (8.5) bands to HIGH, overriding the level.
    assert f.severity is FindingSeverity.HIGH
    assert f.cwe == "CWE-89"
    assert f.endpoint == "app/db.py:21"
    assert f.evidence["engine"] == "opengrep"  # taken from the SARIF tool name
    assert f.evidence["vuln_id_from_tool"] == "python.sqli"


def test_sarif_level_maps_when_no_numeric_score():
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "linter", "rules": []}},
                "results": [
                    {"ruleId": "r1", "level": "warning", "message": {"text": "m"}},
                    {"ruleId": "r2", "level": "note", "message": {"text": "m"}},
                ],
            }
        ]
    }
    findings = get_parser("sarif").parse(sarif)
    assert findings[0].severity is FindingSeverity.MEDIUM  # warning
    assert findings[1].severity is FindingSeverity.INFO  # note


def test_semgrep_native_and_opengrep_label():
    report = {
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-exec",
                "path": "app/run.py",
                "start": {"line": 8},
                "extra": {
                    "message": "Detected subprocess with shell=True",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-78: OS Command Injection"], "owasp": ["A03"]},
                },
            }
        ]
    }
    f = get_parser("semgrep").parse(report)[0]
    assert f.title == "dangerous-exec"
    assert f.severity is FindingSeverity.HIGH
    assert f.cwe == "CWE-78"
    assert f.endpoint == "app/run.py:8"
    assert f.evidence["engine"] == "semgrep"
    # Opengrep is output-compatible; only the engine label changes.
    o = get_parser("opengrep").parse(report)[0]
    assert o.evidence["engine"] == "opengrep"
    assert o.cwe == "CWE-78"


def test_zap_native_alert_mapping():
    report = {
        "site": [
            {
                "@name": "http://target",
                "alerts": [
                    {
                        "pluginid": "40018",
                        "alert": "SQL Injection",
                        "riskcode": "3",
                        "confidence": "2",
                        "riskdesc": "High (Medium)",
                        "desc": "<p>SQLi found</p>",
                        "solution": "<p>Use parameterized queries</p>",
                        "reference": "<p>https://owasp.org</p>",
                        "cweid": "89",
                        "wascid": "19",
                        "instances": [
                            {"uri": "http://target/search?q=1", "method": "GET"},
                            {"uri": "http://target/list?id=2", "method": "GET"},
                        ],
                        "count": "2",
                    }
                ],
            }
        ]
    }
    f = get_parser("zap").parse(report)[0]
    assert f.title == "SQL Injection"
    assert f.severity is FindingSeverity.HIGH  # riskcode 3
    assert f.cwe == "CWE-89"
    assert f.endpoint == "http://target/search?q=1"
    assert f.evidence["endpoints"] == [
        "http://target/search?q=1",
        "http://target/list?id=2",
    ]
    assert f.evidence["mitigation"].startswith("<p>Use parameterized")
    assert f.evidence["plugin_id"] == "40018"


def test_parsers_tolerate_junk_input():
    for tool in ("nuclei", "trivy", "gitleaks", "sarif", "semgrep", "zap", "generic"):
        assert get_parser(tool).parse("") == []
        assert get_parser(tool).parse("{not valid json") == []
        assert get_parser(tool).parse(None) == []


# ===========================================================================
# CRITICAL redaction invariant — via the parser path
# ===========================================================================
def test_gitleaks_parser_never_stores_plaintext_secret():
    findings = get_parser("gitleaks").parse(_GITLEAKS_ROWS)
    assert len(findings) == 2
    for row, f in zip(_GITLEAKS_ROWS, findings):
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
        assert row["Secret"] not in blob, "plaintext Secret leaked through the parser"
        assert row["Match"] not in blob, "raw Match leaked through the parser"
        assert f.payload is None  # payload must never carry the secret/match
        # A redacted, non-reversible fingerprint proves we saw + redacted the secret.
        fp = f.evidence.get("secret_fingerprint")
        assert fp and row["Secret"] not in fp
        assert f.severity is FindingSeverity.HIGH
        assert f.cwe == "CWE-798"


def test_trivy_secret_parser_never_stores_plaintext_secret():
    findings = get_parser("trivy").parse(_TRIVY_REPORT)
    secret = [f for f in findings if f.evidence.get("type") == "secret"][0]
    assert secret.title == "aws-access-key-id: AWS Access Key ID"
    assert secret.severity is FindingSeverity.CRITICAL
    assert secret.endpoint == "app/secrets.env:4"
    assert secret.cwe == "CWE-798"
    assert secret.payload is None
    blob = json.dumps(
        {"e": secret.evidence, "r": secret.raw, "p": secret.payload, "poc": secret.poc},
        default=str,
    )
    assert _PLAINTEXT not in blob, "plaintext secret leaked through the trivy parser"
    assert secret.evidence.get("secret_fingerprint")
    assert _PLAINTEXT not in secret.evidence["secret_fingerprint"]
    # Defense in depth: the plaintext is absent across the WHOLE parse.
    full = json.dumps([{"e": f.evidence, "r": f.raw} for f in findings], default=str)
    assert _PLAINTEXT not in full


# ===========================================================================
# Equivalence with the existing hand-rolled runners (the migration guarantee)
# ===========================================================================
def test_equivalence_nuclei_matches_runner():
    """get_parser('nuclei').parse == [_vuln_from_nuclei(row) ...], list-for-list."""
    expected = [_vuln_from_nuclei(row) for row in _NUCLEI_ROWS]
    got = get_parser("nuclei").parse(_NUCLEI_ROWS)
    assert got == expected
    # And through the JSONL string path a migrated runner would actually use.
    jsonl = "\n".join(json.dumps(r) for r in _NUCLEI_ROWS) + "\n"
    assert get_parser("nuclei").parse(jsonl) == expected


def test_equivalence_trivy_matches_runner(tmp_path):
    """get_parser('trivy').parse(report) == _parse_trivy_json(same report on disk)."""
    report_path = tmp_path / "trivy.0.json"
    report_path.write_text(json.dumps(_TRIVY_REPORT), encoding="utf-8")
    expected = _parse_trivy_json(report_path)
    got = get_parser("trivy").parse(_TRIVY_REPORT)
    assert got == expected
    # str-input path (what a runner reading the report file would pass) also matches.
    assert get_parser("trivy").parse(json.dumps(_TRIVY_REPORT)) == expected


def test_equivalence_gitleaks_matches_runner():
    """get_parser('gitleaks').parse == [_vuln_from_gitleaks(row) ...], list-for-list."""
    expected = [_vuln_from_gitleaks(row) for row in _GITLEAKS_ROWS]
    got = get_parser("gitleaks").parse(_GITLEAKS_ROWS)
    assert got == expected
    assert get_parser("gitleaks").parse(json.dumps(_GITLEAKS_ROWS)) == expected
