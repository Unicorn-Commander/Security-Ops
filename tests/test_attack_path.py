"""Attack-path / exposure-graph tests (spec §6 — console read surface).

Two layers, mirroring the report suite (``test_report.py``):

* the **pure builder** (:func:`app.services.attack_path.build_attack_path_graph`)
  in isolation — no DB, transient ``Finding`` rows + a stub engagement — proving
  host grouping, severity roll-up, the unspecified-host bucket, deterministic
  ordering, and the empty case;
* the **route** (:func:`app.api.attack_path.engagement_attack_path_route`) against a
  real in-memory session, asserting it is org-scoped and tenant-isolated (another
  org's engagement is a 404), per the suite convention of exercising the handler
  directly (no HTTP / auth wiring).
"""

from __future__ import annotations

import uuid

import pytest

from app.api.attack_path import engagement_attack_path_route
from app.core.errors import NotFoundError
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.run import Run, RunMode, RunStatus
from app.services.attack_path import build_attack_path_graph
from tests.conftest import make_engagement, make_org


class _StubEngagement:
    """Minimal duck type for the pure builder — it reads only ``id`` + ``name``."""

    def __init__(self, name: str = "pilot engagement", id: uuid.UUID | None = None):
        self.id = id or uuid.uuid4()
        self.name = name


def _finding(
    severity: FindingSeverity,
    *,
    endpoint: str | None = None,
    title: str = "finding",
    cwe: str | None = None,
    status: FindingStatus = FindingStatus.NEW,
    id: uuid.UUID | None = None,
) -> Finding:
    """A transient (un-persisted) ``Finding`` — the builder never touches a session."""
    return Finding(
        id=id or uuid.uuid4(),
        title=title,
        severity=severity,
        endpoint=endpoint,
        cwe=cwe,
        status=status,
    )


# ---------------------------------------------------------------------------
# Pure builder — host grouping + layered edges
# ---------------------------------------------------------------------------
def test_build_graph_groups_by_host_with_layered_edges():
    eng = _StubEngagement(name="ACME Q3")
    findings = [
        _finding(FindingSeverity.CRITICAL, endpoint="https://app.acme.com/login", title="SQLi"),
        _finding(FindingSeverity.LOW, endpoint="https://app.acme.com/search", title="Verbose error"),
        _finding(FindingSeverity.HIGH, endpoint="https://api.acme.com/v1/users/1", title="IDOR"),
    ]

    graph = build_attack_path_graph(eng, findings)

    # One engagement root + two hosts + three finding leaves.
    types = [n.type for n in graph.nodes]
    assert types.count("engagement") == 1
    assert types.count("host") == 2
    assert types.count("finding") == 3

    root = graph.nodes[0]
    assert root.type == "engagement"
    assert root.id == f"engagement:{eng.id}"
    assert root.label == "ACME Q3"
    assert root.host_count == 2
    assert root.finding_count == 3

    # Hosts are parsed from the endpoints.
    host_labels = {n.label for n in graph.nodes if n.type == "host"}
    assert host_labels == {"app.acme.com", "api.acme.com"}

    # Layered edges: engagement->host for each host, host->finding for each finding.
    kinds = [e.kind for e in graph.edges]
    assert kinds.count("engagement-host") == 2
    assert kinds.count("host-finding") == 3

    # Every edge endpoint references a real node id.
    node_ids = {n.id for n in graph.nodes}
    for edge in graph.edges:
        assert edge.source in node_ids
        assert edge.target in node_ids

    assert graph.summary.node_count == 6
    assert graph.summary.edge_count == 5
    assert graph.summary.host_count == 2
    assert graph.summary.finding_count == 3


# ---------------------------------------------------------------------------
# Pure builder — severity roll-up + host ordering + edge weights
# ---------------------------------------------------------------------------
def test_build_graph_rolls_up_max_severity_per_host_and_root():
    eng = _StubEngagement()
    findings = [
        _finding(FindingSeverity.MEDIUM, endpoint="https://a.example.com/x"),
        _finding(FindingSeverity.CRITICAL, endpoint="https://a.example.com/y"),
        _finding(FindingSeverity.LOW, endpoint="https://b.example.com/z"),
    ]

    graph = build_attack_path_graph(eng, findings)

    hosts = {n.label: n for n in graph.nodes if n.type == "host"}
    # Host severity is the max across its findings.
    assert hosts["a.example.com"].severity == FindingSeverity.CRITICAL
    assert hosts["b.example.com"].severity == FindingSeverity.LOW
    # Root severity is the max across all findings; summary agrees.
    assert graph.nodes[0].severity == FindingSeverity.CRITICAL
    assert graph.summary.max_severity == FindingSeverity.CRITICAL
    assert graph.summary.by_severity == {"CRITICAL": 1, "MEDIUM": 1, "LOW": 1}

    # Hosts are ordered most-severe first.
    host_order = [n.label for n in graph.nodes if n.type == "host"]
    assert host_order == ["a.example.com", "b.example.com"]

    # The engagement->host edge carries the host severity and a weight = finding count.
    edge_by_target = {e.target: e for e in graph.edges if e.kind == "engagement-host"}
    a_edge = edge_by_target[hosts["a.example.com"].id]
    assert a_edge.severity == FindingSeverity.CRITICAL
    assert a_edge.weight == 2


# ---------------------------------------------------------------------------
# Pure builder — findings without a parseable host bucket under one sentinel node
# ---------------------------------------------------------------------------
def test_build_graph_buckets_findings_without_host_and_sorts_it_last():
    eng = _StubEngagement()
    findings = [
        # No endpoint, yet CRITICAL — the sentinel bucket must still sort LAST.
        _finding(FindingSeverity.CRITICAL, endpoint=None, title="No endpoint"),
        _finding(FindingSeverity.LOW, endpoint="https://real.example.com/x", title="On host"),
    ]

    graph = build_attack_path_graph(eng, findings)

    host_order = [n.label for n in graph.nodes if n.type == "host"]
    assert host_order == ["real.example.com", "(unspecified host)"]

    unspecified = next(n for n in graph.nodes if n.label == "(unspecified host)")
    assert unspecified.type == "host"
    assert unspecified.finding_count == 1
    # Its single finding is wired under it.
    child = [e.target for e in graph.edges if e.source == unspecified.id]
    assert len(child) == 1


def test_build_graph_normalizes_host_variants_into_one_node():
    eng = _StubEngagement()
    # URL, host:port, and bare host all normalize to the same host → a single node.
    findings = [
        _finding(FindingSeverity.LOW, endpoint="https://Example.COM/a", title="url"),
        _finding(FindingSeverity.LOW, endpoint="example.com:8443/b", title="hostport"),
        _finding(FindingSeverity.LOW, endpoint="example.com", title="bare"),
    ]

    graph = build_attack_path_graph(eng, findings)

    host_nodes = [n for n in graph.nodes if n.type == "host"]
    assert len(host_nodes) == 1
    assert host_nodes[0].label == "example.com"
    assert host_nodes[0].finding_count == 3


def test_build_graph_orders_finding_leaves_by_severity_then_title():
    eng = _StubEngagement()
    findings = [
        _finding(FindingSeverity.LOW, endpoint="https://h.example.com/a", title="Zebra low"),
        _finding(FindingSeverity.CRITICAL, endpoint="https://h.example.com/b", title="Bravo crit"),
        _finding(FindingSeverity.CRITICAL, endpoint="https://h.example.com/c", title="Alpha crit"),
    ]

    graph = build_attack_path_graph(eng, findings)

    leaf_titles = [n.label for n in graph.nodes if n.type == "finding"]
    # CRITICAL before LOW; within CRITICAL, title ascending — fully deterministic.
    assert leaf_titles == ["Alpha crit", "Bravo crit", "Zebra low"]


# ---------------------------------------------------------------------------
# Pure builder — empty case
# ---------------------------------------------------------------------------
def test_build_graph_empty_findings_is_root_only():
    eng = _StubEngagement(name="quiet engagement")

    graph = build_attack_path_graph(eng, [])

    assert len(graph.nodes) == 1
    root = graph.nodes[0]
    assert root.type == "engagement"
    assert root.label == "quiet engagement"
    assert root.severity is None
    assert root.finding_count == 0
    assert root.host_count == 0
    assert graph.edges == []

    assert graph.summary.node_count == 1
    assert graph.summary.edge_count == 0
    assert graph.summary.host_count == 0
    assert graph.summary.finding_count == 0
    assert graph.summary.by_severity == {}
    assert graph.summary.max_severity is None


# ---------------------------------------------------------------------------
# Route — org-scoped + tenant isolation (another org's engagement is a 404)
# ---------------------------------------------------------------------------
async def _make_run(session, engagement, org, *, status: RunStatus = RunStatus.COMPLETED) -> Run:
    run = Run(
        id=uuid.uuid4(),
        engagement_id=engagement.id,
        org_id=org.id,
        mode=RunMode.STANDARD,
        model_profile="hybrid-local-sweep-verify",
        targets=["example.com"],
        status=status,
    )
    session.add(run)
    await session.flush()
    return run


async def _make_finding(
    session,
    run,
    engagement,
    org,
    *,
    title: str,
    severity: FindingSeverity,
    endpoint: str | None = None,
) -> Finding:
    finding = Finding(
        id=uuid.uuid4(),
        run_id=run.id,
        engagement_id=engagement.id,
        org_id=org.id,
        title=title,
        severity=severity,
        endpoint=endpoint,
        status=FindingStatus.NEW,
    )
    session.add(finding)
    await session.flush()
    return finding


async def test_attack_path_route_is_org_scoped_and_tenant_isolated(db_session):
    org = await make_org(db_session, slug="alpha")
    other = await make_org(db_session, slug="beta")
    eng = await make_engagement(db_session, org)
    other_eng = await make_engagement(db_session, other)
    run = await _make_run(db_session, eng, org)
    other_run = await _make_run(db_session, other_eng, other)

    await _make_finding(
        db_session, run, eng, org,
        title="SQL injection", severity=FindingSeverity.CRITICAL,
        endpoint="https://app.alpha.com/login",
    )
    await _make_finding(
        db_session, run, eng, org,
        title="IDOR", severity=FindingSeverity.HIGH,
        endpoint="https://api.alpha.com/v1/users/1",
    )
    # Cross-org finding must never surface in alpha's graph.
    await _make_finding(
        db_session, other_run, other_eng, other,
        title="Other-org critical", severity=FindingSeverity.CRITICAL,
        endpoint="https://app.beta.com/x",
    )

    graph = await engagement_attack_path_route(eng.id, db_session, org)

    assert graph.engagement_id == eng.id
    # Only alpha's two findings across its two hosts — beta's is excluded.
    assert graph.summary.finding_count == 2
    host_labels = {n.label for n in graph.nodes if n.type == "host"}
    assert host_labels == {"app.alpha.com", "api.alpha.com"}
    assert graph.summary.max_severity == FindingSeverity.CRITICAL

    # Another org's engagement is a 404 for this caller (tenant isolation).
    with pytest.raises(NotFoundError):
        await engagement_attack_path_route(other_eng.id, db_session, org)
