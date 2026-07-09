"""Attack-path / exposure-graph builder (spec §6 — console read surface).

Derives a layered attack-path graph from an engagement and its already-loaded
:class:`~app.models.finding.Finding` rows. The graph is a *pure projection* of
existing findings — it introduces NO new persisted state and needs no Strix
step-log plumbing:

    engagement (root)  →  host / affected asset  →  finding (leaf)

Hosts are parsed from ``finding.endpoint`` with a local, stdlib-only ``_host_of``
that mirrors :func:`app.repositories.targets._host_of` (URL / ``host:port`` / bare
host / bracketed IPv6). Findings whose endpoint is missing or unparseable are
grouped under a single ``(unspecified host)`` bucket so every finding stays
reachable from the root. Severity rolls up: a host node's severity is the max of
its findings, the engagement root's is the max over all findings.

**Purity contract:** :func:`build_attack_path_graph` does NO I/O, opens no session,
and never reads the clock — the route hands it rows already loaded (and
tenant-checked) via the repository. This makes the whole derivation deterministic
and unit-testable without a database, exactly like the report builder
(:mod:`app.reports.builder`). Ordering is fully determined (severity-desc, then
label / title, then id) so the same inputs always yield byte-identical output.

Dependency direction (no cycles): services -> {schemas, models}. Nothing here
imports repositories / api / authz.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable
from urllib.parse import urlsplit

from app.models.finding import FindingSeverity
from app.schemas.attack_path import (
    AttackPathEdge,
    AttackPathGraph,
    AttackPathNode,
    AttackPathSummary,
)

if TYPE_CHECKING:  # typing only — no runtime coupling / cycle
    from app.models.engagement import Engagement
    from app.models.finding import Finding

# Severity ordering, most-severe first — the shared ramp used across the console.
# Higher rank == more severe (INFO=0 … CRITICAL=4).
_SEVERITY_ORDER: list[FindingSeverity] = [
    FindingSeverity.CRITICAL,
    FindingSeverity.HIGH,
    FindingSeverity.MEDIUM,
    FindingSeverity.LOW,
    FindingSeverity.INFO,
]
_SEVERITY_RANK: dict[FindingSeverity, int] = {
    sev: rank for rank, sev in enumerate(reversed(_SEVERITY_ORDER))
}

# Sentinel host id/label for findings with no parseable endpoint host. The id is
# namespaced like every other host node so it never collides with a real host.
_UNSPECIFIED_ID = "host:__unspecified__"
_UNSPECIFIED_LABEL = "(unspecified host)"


def build_attack_path_graph(
    engagement: "Engagement", findings: "Iterable[Finding]"
) -> AttackPathGraph:
    """Project ``findings`` into a layered attack-path graph for ``engagement``.

    Pure and deterministic: no DB, no clock. ``engagement`` supplies the root
    node's id/label; ``findings`` are grouped by parsed host, severity is rolled
    up, and nodes/edges are emitted in a stable order (hosts by severity-desc then
    name; findings by severity-desc then title then id). An engagement with no
    findings yields just the root node, no edges, and a zeroed summary.
    """
    findings = list(findings)

    # Group findings by their parsed host (or the unspecified sentinel).
    by_host: dict[str | None, list["Finding"]] = {}
    for finding in findings:
        host = _host_of(finding.endpoint)
        by_host.setdefault(host, []).append(finding)

    # Order hosts: the unspecified bucket always last, then real hosts most-severe
    # first, ties broken alphabetically — fully deterministic.
    def _host_sort_key(host: str | None) -> tuple:
        rank = _max_rank(by_host[host])
        return (host is None, -rank, host or "")

    ordered_hosts = sorted(by_host, key=_host_sort_key)

    nodes: list[AttackPathNode] = []
    edges: list[AttackPathEdge] = []

    engagement_id = f"engagement:{engagement.id}"
    root_severity = _max_severity(findings)
    nodes.append(
        AttackPathNode(
            id=engagement_id,
            type="engagement",
            label=engagement.name,
            severity=root_severity,
            finding_count=len(findings),
            host_count=len(ordered_hosts),
        )
    )

    for host in ordered_hosts:
        host_findings = by_host[host]
        host_id = _UNSPECIFIED_ID if host is None else f"host:{host}"
        host_label = _UNSPECIFIED_LABEL if host is None else host
        host_severity = _max_severity(host_findings)

        nodes.append(
            AttackPathNode(
                id=host_id,
                type="host",
                label=host_label,
                severity=host_severity,
                finding_count=len(host_findings),
            )
        )
        edges.append(
            AttackPathEdge(
                source=engagement_id,
                target=host_id,
                kind="engagement-host",
                severity=host_severity,
                weight=len(host_findings),
            )
        )

        for finding in sorted(host_findings, key=_finding_sort_key):
            finding_node_id = f"finding:{finding.id}"
            nodes.append(
                AttackPathNode(
                    id=finding_node_id,
                    type="finding",
                    label=finding.title,
                    severity=finding.severity,
                    cwe=finding.cwe,
                    status=finding.status,
                    endpoint=finding.endpoint,
                    finding_id=finding.id,
                )
            )
            edges.append(
                AttackPathEdge(
                    source=host_id,
                    target=finding_node_id,
                    kind="host-finding",
                    severity=finding.severity,
                    weight=1,
                )
            )

    summary = AttackPathSummary(
        node_count=len(nodes),
        edge_count=len(edges),
        host_count=len(ordered_hosts),
        finding_count=len(findings),
        by_severity=_severity_histogram(findings),
        max_severity=root_severity,
    )
    return AttackPathGraph(
        engagement_id=engagement.id,
        engagement_name=engagement.name,
        nodes=nodes,
        edges=edges,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Pure helpers — stdlib only, fully deterministic.
# ---------------------------------------------------------------------------
def _finding_sort_key(finding: "Finding") -> tuple:
    """Stable leaf ordering: severity-desc, then title, then id (always present)."""
    return (-_SEVERITY_RANK.get(finding.severity, -1), finding.title or "", str(finding.id))


def _max_rank(findings: "list[Finding]") -> int:
    """Highest severity rank across ``findings`` (``-1`` when empty)."""
    return max((_SEVERITY_RANK.get(f.severity, -1) for f in findings), default=-1)


def _max_severity(findings: "Iterable[Finding]") -> FindingSeverity | None:
    """The most-severe :class:`FindingSeverity` across ``findings`` (or ``None``)."""
    best: FindingSeverity | None = None
    best_rank = -1
    for finding in findings:
        rank = _SEVERITY_RANK.get(finding.severity, -1)
        if rank > best_rank:
            best_rank = rank
            best = finding.severity
    return best


def _severity_histogram(findings: "Iterable[Finding]") -> dict[str, int]:
    """``{severity.value: count}`` over ``findings`` — absent severities omitted
    (mirrors ``OverviewRead.findings.by_severity``)."""
    histogram: dict[str, int] = {}
    for finding in findings:
        key = getattr(finding.severity, "value", str(finding.severity))
        histogram[key] = histogram.get(key, 0) + 1
    return histogram


def _host_of(endpoint: str | None) -> str | None:
    """Lowercased host from a URL / ``host:port`` / bare host string, or ``None``.

    Mirrors :func:`app.repositories.targets._host_of` but is kept LOCAL and pure
    (stdlib only) so the builder depends on nothing but schemas + models. A missing
    or empty endpoint (and any parse that yields no host) returns ``None`` — the
    caller buckets those findings under the ``(unspecified host)`` node.
    """
    text = (endpoint or "").strip()
    if not text:
        return None
    netloc = urlsplit(text).netloc if "://" in text else text
    if not netloc:  # e.g. "example.com/path" parses entirely into .path
        netloc = text
    netloc = netloc.rsplit("@", 1)[-1]  # drop any userinfo
    netloc = netloc.split("/", 1)[0]  # drop path (scheme-less inputs)
    if netloc.startswith("["):  # bracketed IPv6 literal, optionally [..]:port
        host = netloc[1:].split("]", 1)[0]
    elif netloc.count(":") == 1:  # host:port (single colon) — not a bare IPv6
        host = netloc.split(":", 1)[0]
    else:  # bare host, or bare IPv6 literal (multiple colons)
        host = netloc
    host = host.strip().rstrip(".").lower()
    return host or None


__all__ = ["build_attack_path_graph"]
