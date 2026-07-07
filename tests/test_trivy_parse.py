"""Trivy JSON parsing (engine #4) — the Results[] → normalized-finding contract.

Pins the mapping from trivy's JSON report (``{"Results": [...]}`` with
``Vulnerabilities`` / ``Misconfigurations`` / ``Secrets`` arrays) onto the shared
:class:`ParsedVulnerability` shape, using the field names a real
``trivy image --format json`` run emits. Tolerant of blank/malformed reports and a
missing ``Results`` block.

CRITICAL: a plaintext secret from a trivy ``Secrets`` result must NEVER appear in a
parsed finding — ``test_plaintext_secret_never_stored`` asserts the same redaction
invariant as the gitleaks suite.
"""

from __future__ import annotations

import json

from app.engine.trivy_runner import (
    _build_trivy_command,
    _finding_from_trivy_secret,
    _parse_trivy_json,
    _trivy_target_mode,
    _vuln_from_trivy_vuln,
)
from app.models.finding import FindingSeverity

_PLAINTEXT_SECRET = "AKIAIOSFODNN7TRIVYEXAMPLE"

_REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": "nginx:1.21",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "nginx:1.21 (debian 11.2)",
            "Class": "os-pkgs",
            "Type": "debian",
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
            "Class": "config",
            "Type": "dockerfile",
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
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key ID",
                    "StartLine": 4,
                    "EndLine": 4,
                    "Match": f"AWS_KEY={_PLAINTEXT_SECRET}",
                    "Code": {"Lines": [{"Number": 4, "Content": f"AWS_KEY={_PLAINTEXT_SECRET}"}]},
                }
            ],
        },
    ],
}


def _write_json(tmp_path, report, name="trivy.0.json"):
    p = tmp_path / name
    p.write_text(json.dumps(report), encoding="utf-8")
    return p


def test_parses_vuln_misconfig_and_secret(tmp_path):
    p = _write_json(tmp_path, _REPORT)
    findings = _parse_trivy_json(p)
    assert len(findings) == 3  # one vuln + one misconfig + one secret


def test_maps_vulnerability(tmp_path):
    v = _REPORT["Results"][0]["Vulnerabilities"][0]
    f = _vuln_from_trivy_vuln(v, "nginx:1.21 (debian 11.2)")
    assert f.title == "CVE-2021-3711: openssl: SM2 Decryption Buffer Overflow"
    assert f.severity == FindingSeverity.CRITICAL
    assert f.endpoint == "openssl@1.1.1k-1"
    assert f.cwe == "CWE-787"
    assert f.payload == "Upgrade openssl to 1.1.1l-1"  # fix hint
    assert f.evidence["engine"] == "trivy"
    assert f.evidence["vuln_id"] == "CVE-2021-3711"
    assert f.evidence["fixed"] == "1.1.1l-1"


def test_maps_misconfig(tmp_path):
    findings = _parse_trivy_json(_write_json(tmp_path, _REPORT))
    misconf = [f for f in findings if f.evidence.get("type") == "misconfig"][0]
    assert misconf.title == "DS002: Image user should not be 'root'"
    assert misconf.severity == FindingSeverity.HIGH
    assert misconf.payload == "Add a USER command."
    assert misconf.cwe is None


def test_severity_map_and_unknown(tmp_path):
    v = {"VulnerabilityID": "CVE-X", "Severity": "LOW", "PkgName": "p", "InstalledVersion": "1"}
    assert _vuln_from_trivy_vuln(v, "t").severity == FindingSeverity.LOW
    # Unknown severity defaults to MEDIUM (surfaces for review rather than hiding).
    v2 = {"VulnerabilityID": "CVE-Y", "Severity": "UNKNOWN", "PkgName": "p", "InstalledVersion": "1"}
    assert _vuln_from_trivy_vuln(v2, "t").severity == FindingSeverity.MEDIUM


def test_plaintext_secret_never_stored(tmp_path):
    """The redaction invariant for trivy Secrets results."""
    secret = _REPORT["Results"][2]["Secrets"][0]
    f = _finding_from_trivy_secret(secret, "app/secrets.env")
    assert f.title == "aws-access-key-id: AWS Access Key ID"
    assert f.severity == FindingSeverity.CRITICAL
    assert f.endpoint == "app/secrets.env:4"
    assert f.cwe == "CWE-798"
    assert f.payload is None
    blob = json.dumps(
        {
            "title": f.title,
            "endpoint": f.endpoint,
            "payload": f.payload,
            "poc": f.poc,
            "evidence": f.evidence,
            "raw": f.raw,
        },
        default=str,
    )
    assert _PLAINTEXT_SECRET not in blob, "plaintext secret leaked into finding"
    assert f.evidence.get("secret_fingerprint")
    assert _PLAINTEXT_SECRET not in f.evidence["secret_fingerprint"]

    # And through the full report parse (defense in depth).
    findings = _parse_trivy_json(_write_json(tmp_path, _REPORT))
    full = json.dumps([{"e": x.evidence, "r": x.raw, "p": x.payload} for x in findings], default=str)
    assert _PLAINTEXT_SECRET not in full


def test_target_mode_heuristic(tmp_path):
    assert _trivy_target_mode("nginx:1.21") == "image"
    assert _trivy_target_mode("registry.example.com/team/app:sha-abc") == "image"
    assert _trivy_target_mode("https://github.com/org/repo.git") == "repo"
    assert _trivy_target_mode("demo@example.invalid:org/repo.git") == "repo"
    assert _trivy_target_mode(str(tmp_path)) == "fs"  # existing local dir


def test_build_command_shape(tmp_path):
    cmd = _build_trivy_command(["nginx:1.21", "https://github.com/o/r.git"], tmp_path)
    assert cmd[0] == "bash" and cmd[1] == "-c"
    script = cmd[2]
    assert "trivy image" in script
    assert "trivy repo" in script
    assert "--scanners vuln,secret,misconfig" in script


def test_tolerates_blank_and_malformed_reports(tmp_path):
    assert _parse_trivy_json(tmp_path / "nope.json") == []  # missing
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    assert _parse_trivy_json(empty) == []  # blank
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert _parse_trivy_json(bad) == []  # malformed
    no_results = tmp_path / "nores.json"
    no_results.write_text(json.dumps({"SchemaVersion": 2}), encoding="utf-8")
    assert _parse_trivy_json(no_results) == []  # no Results block
