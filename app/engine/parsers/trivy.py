"""app.engine.parsers.trivy — Trivy ``--format json`` -> DojoFinding.

Re-expresses the field maps proven in ``trivy_runner`` (``_vuln_from_trivy_vuln`` /
``_finding_from_trivy_misconfig`` / ``_finding_from_trivy_secret``) on the DefectDojo
intermediate, walking ``Results[]`` -> ``{Vulnerabilities, Misconfigurations,
Secrets}`` in the SAME order the runner does, so the emitted
``list[ParsedVulnerability]`` is identical (pinned in
``tests/test_parsers_defectdojo.py``).

SECURITY — a Trivy ``Secrets`` result carries the raw ``Match`` / ``Code``. This parser
redacts to a non-reversible fingerprint and keeps only the sanitized item (``Match`` /
``Code`` stripped) as ``raw``, reusing the runner's own ``_redact_secret`` /
``_sanitize_trivy_secret`` so redaction stays single-sourced. Plaintext never reaches a
DojoFinding field.
"""

from __future__ import annotations

from typing import Any

from app.engine.gitleaks_runner import _redact_secret
from app.engine.parsers.base import (
    DojoFinding,
    Parser,
    _first,
    _to_str,
    first_scalar,
    load_report,
    map_severity,
)
from app.engine.trivy_runner import (
    _SECRET_CWE,
    _SECRET_SEVERITY,
    _sanitize_trivy_secret,
)


def dojo_from_trivy_vuln(item: dict[str, Any], target: str | None) -> DojoFinding:
    vuln_id = _to_str(_first(item, "VulnerabilityID", "vulnerabilityID", "id"))
    name = _to_str(_first(item, "Title", "title"))
    title = f"{vuln_id}: {name}" if vuln_id and name else (name or vuln_id or "Vulnerability")
    pkg = _to_str(_first(item, "PkgName", "pkgName"))
    installed = _to_str(_first(item, "InstalledVersion", "installedVersion"))
    fixed = _to_str(_first(item, "FixedVersion", "fixedVersion"))
    endpoint = f"{pkg}@{installed}" if pkg and installed else pkg
    payload = (
        f"Upgrade {pkg} to {fixed}"
        if pkg and fixed
        else (f"Fixed in {fixed}" if fixed else None)
    )
    primary_url = _to_str(_first(item, "PrimaryURL", "primaryURL"))
    return DojoFinding(
        tool="trivy",
        title=str(title),
        severity=_first(item, "Severity", "severity"),
        cwe=first_scalar(item.get("CweIDs") or item.get("cweIDs")),
        endpoint=endpoint,
        payload=payload,
        poc=primary_url,
        description=_to_str(_first(item, "Description", "description")),
        references=item.get("References") or item.get("references"),
        evidence_extra={
            "type": "vulnerability",
            "vuln_id": vuln_id,
            "pkg": pkg,
            "installed": installed,
            "fixed": fixed,
            "target": target,
            "primary_url": primary_url,
        },
        raw=item,
    )


def dojo_from_trivy_misconfig(item: dict[str, Any], target: str | None) -> DojoFinding:
    misconf_id = _to_str(_first(item, "ID", "id", "AVDID", "avdID"))
    name = _to_str(_first(item, "Title", "title"))
    title = (
        f"{misconf_id}: {name}"
        if misconf_id and name
        else (name or misconf_id or "Misconfiguration")
    )
    resolution = _to_str(_first(item, "Resolution", "resolution"))
    return DojoFinding(
        tool="trivy",
        title=str(title),
        severity=_first(item, "Severity", "severity"),
        cwe=None,  # trivy misconfigs are keyed by AVD ids, not CWE.
        endpoint=target,
        payload=resolution,
        poc=_to_str(_first(item, "PrimaryURL", "primaryURL")),
        description=_to_str(_first(item, "Description", "description")),
        references=item.get("References") or item.get("references"),
        evidence_extra={
            "type": "misconfig",
            "misconf_id": misconf_id,
            "target": target,
            "message": _to_str(_first(item, "Message", "message")),
            "resolution": resolution,
        },
        raw=item,
    )


def dojo_from_trivy_secret(item: dict[str, Any], target: str | None) -> DojoFinding:
    rule_id = _to_str(_first(item, "RuleID", "ruleID", "rule_id"))
    category = _to_str(_first(item, "Category", "category"))
    name = _to_str(_first(item, "Title", "title"))
    title = (
        f"{rule_id}: {name}"
        if rule_id and name
        else (name or category or rule_id or "Secret detected")
    )
    start_line = _first(item, "StartLine", "startLine", "start_line")
    endpoint = f"{target}:{start_line}" if target and start_line is not None else target
    raw_severity = _first(item, "Severity", "severity")
    severity = map_severity(raw_severity) if raw_severity else _SECRET_SEVERITY
    # Redact the plaintext match to a non-reversible fingerprint; drop the raw match.
    secret_fingerprint = _redact_secret(_first(item, "Match", "match", default=None))
    return DojoFinding(
        tool="trivy",
        title=str(title),
        severity=severity,
        cwe=_SECRET_CWE,
        endpoint=endpoint,
        payload=None,  # NEVER the raw match/code.
        poc=None,
        line=start_line,
        evidence_extra={
            "type": "secret",
            "rule_id": rule_id,
            "category": category,
            "target": target,
            "severity_raw": _to_str(raw_severity),
            # Redacted fingerprint — NEVER the plaintext match/code.
            "secret_fingerprint": secret_fingerprint,
        },
        raw=_sanitize_trivy_secret(item),  # Match/Code stripped.
    )


class TrivyParser(Parser):
    tool = "trivy"

    def parse_findings(self, report: dict | list | str | bytes) -> list[DojoFinding]:
        data = load_report(report)
        if not isinstance(data, dict):
            return []
        results = data.get("Results")
        if not isinstance(results, list):
            return []
        out: list[DojoFinding] = []
        for result in results:
            if not isinstance(result, dict):
                continue
            target = _to_str(_first(result, "Target", "target"))
            for vuln in result.get("Vulnerabilities") or []:
                if isinstance(vuln, dict):
                    out.append(dojo_from_trivy_vuln(vuln, target))
            for misconf in result.get("Misconfigurations") or []:
                if isinstance(misconf, dict):
                    out.append(dojo_from_trivy_misconfig(misconf, target))
            for secret in result.get("Secrets") or []:
                if isinstance(secret, dict):
                    out.append(dojo_from_trivy_secret(secret, target))
        return out
