"""EPSS / CISA KEV enrichment for CVE findings.

Best-effort enrichment only: any network or parsing failure is swallowed so the
scan pipeline never fails because an external feed was unavailable.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

log = logging.getLogger("secops.engine.enrich")

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_EPSS_URL = "https://api.first.org/data/v1/epss"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# TODO ttl: refresh this cache periodically instead of once per process.
_KEV_SET: set[str] | None = None


def _cves_from_text(value: Any) -> set[str]:
    text = "" if value is None else str(value)
    return {m.group(0).upper() for m in _CVE_RE.finditer(text)}


def _finding_cves(finding: Any) -> set[str]:
    cves: set[str] = set()
    for key in ("title", "endpoint", "payload", "poc", "cwe", "fingerprint"):
        cves.update(_cves_from_text(getattr(finding, key, None)))
    evidence = getattr(finding, "evidence", None)
    if isinstance(evidence, dict):
        cves.update(_cves_from_text(json.dumps(evidence, default=str)))
    raw = getattr(finding, "raw", None)
    if raw is not None:
        cves.update(_cves_from_text(json.dumps(raw, default=str)))
    return cves


async def _load_kev_set(client: httpx.AsyncClient) -> set[str]:
    global _KEV_SET
    if _KEV_SET is not None:
        return _KEV_SET
    resp = await client.get(_KEV_URL)
    resp.raise_for_status()
    data = resp.json()
    items = data.get("vulnerabilities") if isinstance(data, dict) else None
    kev = {
        str(item.get("cveID")).upper()
        for item in items or []
        if isinstance(item, dict) and item.get("cveID")
    }
    _KEV_SET = kev
    return kev


async def enrich_cves(findings: list[Any]) -> None:
    """Mutate finding evidence in place with EPSS / KEV metadata when available."""
    if not findings:
        return

    cves = sorted({cve for finding in findings for cve in _finding_cves(finding)})
    if not cves:
        return

    epss_by_cve: dict[str, tuple[float, float]] = {}
    kev_set: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            kev_set = await _load_kev_set(client)

            for i in range(0, len(cves), 100):
                batch = cves[i : i + 100]
                resp = await client.get(_EPSS_URL, params={"cve": ",".join(batch)})
                resp.raise_for_status()
                data = resp.json()
                rows = data.get("data") if isinstance(data, dict) else None
                for row in rows or []:
                    if not isinstance(row, dict):
                        continue
                    cve = str(row.get("cve") or "").upper()
                    if not cve:
                        continue
                    score = row.get("epss")
                    percentile = row.get("percentile")
                    try:
                        epss_by_cve[cve] = (float(score), float(percentile))
                    except (TypeError, ValueError):
                        continue
    except Exception as exc:  # noqa: BLE001 - the scan must continue
        log.warning("cve enrichment unavailable: %s", exc)
        return

    for finding in findings:
        cves_for_finding = _finding_cves(finding)
        if not cves_for_finding:
            continue
        chosen = next((cve for cve in cves if cve in cves_for_finding), None)
        if chosen is None:
            continue
        evidence = dict(getattr(finding, "evidence", None) or {})
        epss = epss_by_cve.get(chosen)
        if epss is not None:
            evidence["epss"] = {"score": epss[0], "percentile": epss[1]}
        evidence["kev"] = chosen in kev_set
        finding.evidence = evidence
