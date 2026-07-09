"""app.engine.parsers.gitleaks — Gitleaks JSON report -> DojoFinding.

Re-expresses the field map proven in ``gitleaks_runner._vuln_from_gitleaks`` on the
DefectDojo intermediate so ``get_parser("gitleaks").parse(report)`` emits a
``list[ParsedVulnerability]`` identical to the runner (pinned in
``tests/test_parsers_defectdojo.py``). Input may be Gitleaks' raw JSON text (a
top-level array of leak objects) or an already-decoded list.

SECURITY — a gitleaks leak object carries the raw ``Secret`` / ``Match``. This parser
redacts the secret to a non-reversible fingerprint (``prefix4…(len=N)``) and keeps
only the sanitized item (``Secret`` / ``Match`` stripped) as ``raw``, reusing the
runner's own ``_redact_secret`` / ``_sanitize_gitleaks_item``. Plaintext never reaches
a DojoFinding field — the redaction invariant test enforces this.
"""

from __future__ import annotations

from typing import Any

from app.engine.gitleaks_runner import (
    _SECRET_CWE,
    _SECRET_SEVERITY,
    _redact_secret,
    _sanitize_gitleaks_item,
)
from app.engine.parsers.base import (
    DojoFinding,
    Parser,
    _first,
    _to_str,
    load_report,
)


def dojo_from_gitleaks(item: dict[str, Any]) -> DojoFinding:
    rule_id = _to_str(_first(item, "RuleID", "ruleID", "rule_id"))
    title = _to_str(_first(item, "Description", "description")) or rule_id or "Secret detected"
    file = _to_str(_first(item, "File", "file"))
    start_line = _first(item, "StartLine", "startLine", "start_line")
    endpoint = f"{file}:{start_line}" if file and start_line is not None else file
    # gitleaks' own "Fingerprint" is a LOCATION id (``file:rule:line``) — NOT the
    # secret, so it is safe to keep and use as the PoC reference.
    gl_fingerprint = _to_str(_first(item, "Fingerprint", "fingerprint"))
    # Redact the plaintext to a non-reversible fingerprint; the raw secret is dropped.
    secret_fingerprint = _redact_secret(_first(item, "Secret", "secret", default=None))
    return DojoFinding(
        tool="gitleaks",
        title=str(title),
        severity=_SECRET_SEVERITY,  # secrets are HIGH by default.
        cwe=_SECRET_CWE,  # hard-coded credentials.
        endpoint=endpoint,
        payload=None,  # NEVER the raw match/secret.
        poc=gl_fingerprint,  # location id, not the secret.
        file_path=file,
        line=start_line,
        tags=item.get("Tags") or item.get("tags"),
        evidence_extra={
            "rule_id": rule_id,
            "commit": _to_str(_first(item, "Commit", "commit")),
            "author": _to_str(_first(item, "Author", "author")),
            "email": _to_str(_first(item, "Email", "email")),
            "date": _to_str(_first(item, "Date", "date")),
            "gitleaks_fingerprint": gl_fingerprint,
            # Redacted fingerprint of the secret — NEVER the plaintext.
            "secret_fingerprint": secret_fingerprint,
        },
        raw=_sanitize_gitleaks_item(item),  # Secret/Match stripped.
    )


class GitleaksParser(Parser):
    tool = "gitleaks"

    def parse_findings(self, report: dict | list | str | bytes) -> list[DojoFinding]:
        data = load_report(report)
        if isinstance(data, dict):
            # Defensive: some gitleaks versions emit an object wrapper.
            data = data.get("findings") if isinstance(data.get("findings"), list) else None
        if not isinstance(data, list):
            return []
        return [dojo_from_gitleaks(item) for item in data if isinstance(item, dict)]
