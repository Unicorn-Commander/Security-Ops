"""app.engine.parsers.zap — OWASP ZAP -> DojoFinding (native JSON or SARIF).

ZAP's traditional JSON report nests alerts under ``site[].alerts[]``; each alert has a
``riskcode`` (0-3), a ``cweid``, an HTML ``desc`` / ``solution``, and a list of
``instances`` (the affected URIs). This parser maps that shape, and — because modern
ZAP can also export SARIF — delegates a ``{"runs": [...]}`` document to the shared
SARIF parser. One alert becomes one finding; the affected URIs populate ``endpoints``.
"""

from __future__ import annotations

from typing import Any

from app.engine.parsers.base import (
    DojoFinding,
    Parser,
    _first,
    _to_str,
    load_report,
    map_severity,
)
from app.engine.parsers.sarif import parse_sarif
from app.models.finding import FindingSeverity

# ZAP riskcode -> severity (its own risk rating; INFO=0 .. HIGH=3).
_RISKCODE_SEVERITY: dict[str, FindingSeverity] = {
    "0": FindingSeverity.INFO,
    "1": FindingSeverity.LOW,
    "2": FindingSeverity.MEDIUM,
    "3": FindingSeverity.HIGH,
}


def _zap_severity(alert: dict[str, Any]) -> FindingSeverity:
    riskcode = _to_str(_first(alert, "riskcode", "riskCode"))
    if riskcode is not None and riskcode in _RISKCODE_SEVERITY:
        return _RISKCODE_SEVERITY[riskcode]
    # Fall back to the word in riskdesc ("High (Medium)") via the shared map.
    riskdesc = _to_str(_first(alert, "riskdesc", "riskDesc")) or ""
    return map_severity(riskdesc.split(" ")[0]) if riskdesc else FindingSeverity.MEDIUM


def dojo_from_zap_alert(alert: dict[str, Any], site: str | None) -> DojoFinding:
    title = _to_str(_first(alert, "alert", "name")) or "ZAP alert"
    instances = alert.get("instances") if isinstance(alert.get("instances"), list) else []
    uris = [
        _to_str(inst.get("uri"))
        for inst in instances
        if isinstance(inst, dict) and inst.get("uri")
    ]
    uris = [u for u in uris if u]
    endpoint = uris[0] if uris else site
    cweid = _first(alert, "cweid", "cweId")

    return DojoFinding(
        tool="zap",
        title=str(title),
        severity=_zap_severity(alert),
        cwe=cweid if cweid not in (None, "", "-1") else None,
        endpoint=endpoint,
        payload=None,
        poc=uris[0] if uris else None,
        description=_to_str(_first(alert, "desc", "description")),
        mitigation=_to_str(_first(alert, "solution", "mitigation")),
        references=_to_str(_first(alert, "reference", "references")),
        endpoints=uris or None,
        vuln_id_from_tool=_to_str(_first(alert, "pluginid", "pluginId", "alertRef")),
        evidence_extra={
            "plugin_id": _to_str(_first(alert, "pluginid", "pluginId")),
            "wascid": _to_str(_first(alert, "wascid", "wascId")),
            "confidence": _to_str(alert.get("confidence")),
            "risk_desc": _to_str(_first(alert, "riskdesc", "riskDesc")),
            "count": _to_str(alert.get("count")),
            "site": site,
        },
        raw=alert,
    )


class ZapParser(Parser):
    tool = "zap"

    def parse_findings(self, report: dict | list | str | bytes) -> list[DojoFinding]:
        data = load_report(report)
        if isinstance(data, dict) and isinstance(data.get("runs"), list):
            return parse_sarif(data, tool_name=self.tool)
        if not isinstance(data, dict):
            return []
        sites = data.get("site")
        if isinstance(sites, dict):  # single-site reports are sometimes an object
            sites = [sites]
        if not isinstance(sites, list):
            return []
        out: list[DojoFinding] = []
        for site in sites:
            if not isinstance(site, dict):
                continue
            site_name = _to_str(_first(site, "@name", "name", "@host", "host"))
            for alert in site.get("alerts") or []:
                if isinstance(alert, dict):
                    out.append(dojo_from_zap_alert(alert, site_name))
        return out
