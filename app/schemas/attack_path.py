"""Attack-path / exposure-graph schema (spec §6 — console read surface).

Typed contract for ``GET /engagements/{id}/attack-path``. The graph is *derived*
from the engagement's stored :class:`~app.models.finding.Finding` rows — it adds
no new persisted state — so these models mirror what the pure builder
(:func:`app.services.attack_path.build_attack_path_graph`) emits, not an ORM table.

Shape: a layered graph the console renders as an inline SVG.

* **nodes** — one ``engagement`` root, one ``host`` per distinct affected asset
  (parsed from ``finding.endpoint``), and one ``finding`` leaf per vulnerability;
* **edges** — ``engagement-host`` and ``host-finding`` links, each carrying the
  rolled-up ``severity`` and a ``weight`` so the UI can size/colour them;
* **summary** — node/edge/host/finding counts, the per-severity histogram, and the
  single highest severity on any path (the headline "worst exposure").

Node ids are namespaced (``engagement:<uuid>`` / ``host:<host>`` / ``finding:<uuid>``)
so they never collide and an edge's ``source``/``target`` unambiguously reference a
node. Every field is severity-typed against :class:`FindingSeverity` (serialised to
its ``.value`` string) so the frontend reuses the same severity ramp as the rest of
the console.
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, Field

from app.models.finding import FindingSeverity, FindingStatus


class AttackPathNode(BaseModel):
    """One vertex of the exposure graph.

    ``type`` selects the layer (engagement root → host → finding leaf). ``severity``
    is the max severity *at or under* the node (``None`` only when a node has no
    findings — e.g. an engagement with an empty inbox). The leaf-only metadata
    fields (``cwe`` / ``status`` / ``endpoint`` / ``finding_id``) are ``None`` for
    engagement and host nodes.
    """

    id: str
    type: Literal["engagement", "host", "finding"]
    label: str
    severity: FindingSeverity | None = None
    # Findings at/under this node: total for the engagement root, per-host for a
    # host node, 0 for a finding leaf.
    finding_count: int = 0
    # Distinct affected hosts — set on the engagement root only.
    host_count: int | None = None
    # Finding-leaf metadata (None for engagement / host nodes).
    cwe: str | None = None
    status: FindingStatus | None = None
    endpoint: str | None = None
    finding_id: uuid.UUID | None = None


class AttackPathEdge(BaseModel):
    """A directed link between two nodes.

    ``kind`` mirrors the layer boundary it crosses. ``severity`` and ``weight`` are
    the rolled-up encodings the UI uses to colour and size the link: an
    ``engagement-host`` edge carries the host's max severity and its finding count;
    a ``host-finding`` edge carries the finding's own severity and weight ``1``.
    """

    source: str
    target: str
    kind: Literal["engagement-host", "host-finding"]
    severity: FindingSeverity | None = None
    weight: int = 1


class AttackPathSummary(BaseModel):
    """Headline counts for the graph.

    ``by_severity`` is keyed by the enum ``.value`` string actually present
    (absent severities are omitted, mirroring the overview schema), and counts
    findings only. ``max_severity`` is the single worst severity on any path — the
    console's "worst exposure" read.
    """

    node_count: int
    edge_count: int
    host_count: int
    finding_count: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    max_severity: FindingSeverity | None = None


class AttackPathGraph(BaseModel):
    """The derived attack-path graph for one engagement (read-only)."""

    engagement_id: uuid.UUID
    engagement_name: str
    nodes: list[AttackPathNode] = Field(default_factory=list)
    edges: list[AttackPathEdge] = Field(default_factory=list)
    summary: AttackPathSummary
