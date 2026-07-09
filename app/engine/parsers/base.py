"""app.engine.parsers.base — the tool-agnostic normalization spine.

This module defines the two shapes that make "wire a CLI + point at a parser" the
whole cost of adding a scanner:

* :class:`DojoFinding` — a DefectDojo-style intermediate finding. It carries the
  *superset* of fields DefectDojo's parser corpus normalizes onto (title, severity,
  description, mitigation, cwe, cve, cvssv3, file_path, line, component_name/version,
  references, unique_id_from_tool, vuln_id_from_tool, epss_score, endpoints, tags …).
  A concrete parser's only job is to translate its tool's NATIVE json into a list of
  these.
* :class:`Parser` — the ABC every concrete parser implements. It exposes
  :meth:`Parser.parse` returning ``list[ParsedVulnerability]`` (the canonical internal
  finding shape ``StrixRunner._store_findings`` persists), built by mapping each
  :class:`DojoFinding` through :meth:`DojoFinding.to_parsed_vulnerability`.

Provenance / license: the intermediate SHAPE and the "one small parser per tool
funnels into a common normalizer" architecture are modeled on DefectDojo
(github.com/DefectDojo/django-DefectDojo, BSD-3-Clause). This is an ORIGINAL
re-implementation of that *approach* against Security-Ops' own
:class:`ParsedVulnerability` — none of DefectDojo's Django-coupled code is vendored or
copied. We owe them the idea, not the bytes.

Normalization guarantees (match the existing hand-rolled runners exactly so behavior
is preserved when a runner later migrates — see the migration note below):

* Severity → :func:`normalize_severity`, which reuses ``strix_runner.map_severity``:
  an unknown / missing severity becomes ``MEDIUM`` (so it surfaces for review rather
  than hiding as INFO), and the raw string is retained in evidence by the parser.
  A parser that already resolved a floor severity (e.g. a leaked secret is HIGH)
  passes a :class:`FindingSeverity` enum straight through.
* CWE → :func:`normalize_cwe`, which reuses ``strix_runner._normalize_cwe`` to produce
  ``CWE-<n>`` from a bare integer and pass an already-``CWE-``-prefixed string through.
* :meth:`DojoFinding.to_parsed_vulnerability` funnels EVERYTHING that has no
  first-class ``ParsedVulnerability`` home (description, mitigation, cve, cvssv3,
  file_path, line, component, references, epss, tool ids, extra endpoints, and the
  per-tool ``evidence_extra`` bag) into ``evidence``, then drops ``None`` values
  (``raw`` is always kept) — the same filter the existing runners apply.

Migration path (deliberately NOT done here to avoid regressing the live runners):
a runner such as :class:`~app.engine.nuclei_runner.NucleiRunner` can drop its private
``_parse_*`` / ``_vuln_from_*`` helpers and, in ``_build_result``, do::

    from app.engine.parsers import get_parser
    report = (invocation.run_dir / "nuclei.jsonl").read_text("utf-8")
    findings = get_parser("nuclei").parse(report)

The equivalence tests in ``tests/test_parsers_defectdojo.py`` prove that swap emits an
identical ``list[ParsedVulnerability]`` for nuclei, trivy, and gitleaks before anyone
flips a runner over.

Dependency direction (no cycles): parsers -> {engine.strix_runner,
engine.gitleaks_runner, engine.trivy_runner} for the proven field maps + the secret
redaction. The runners do NOT import parsers (the swap above is opt-in), so there is
no cycle; nothing else imports this package except the parser registry and the tests.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field
from typing import Any, ClassVar, Iterator

# Reuse the canonical finding shape + the proven normalization primitives. Importing
# the "private" helpers is the established engine-layer pattern (nuclei_runner and
# trivy_runner already import `_first`/`_to_str`/`map_severity` from strix_runner).
from app.engine.strix_runner import (  # noqa: F401  (re-exported for tool parsers)
    ParsedVulnerability,
    _first,
    _normalize_cwe,
    _to_float,
    _to_str,
    map_severity,
)
from app.models.finding import FindingSeverity

__all__ = [
    "DojoFinding",
    "Parser",
    "ParsedVulnerability",
    "normalize_severity",
    "normalize_cwe",
    "first_scalar",
    "load_report",
    "iter_jsonl",
    # re-exported strix primitives (so tool parsers import from one place)
    "_first",
    "_to_str",
    "_to_float",
]


# ---------------------------------------------------------------------------
# Normalization primitives
# ---------------------------------------------------------------------------
def normalize_severity(value: Any) -> FindingSeverity:
    """Normalize a tool's severity to :class:`FindingSeverity`.

    A parser that already resolved the severity (e.g. a fixed floor for a leaked
    secret) passes the enum straight through; anything else — a raw string or
    ``None`` — is mapped via ``strix_runner.map_severity`` (unknown/missing → MEDIUM).
    """
    if isinstance(value, FindingSeverity):
        return value
    return map_severity(value)


def normalize_cwe(value: Any) -> str | None:
    """Normalize a CWE to ``CWE-<n>`` (reuses ``strix_runner._normalize_cwe``)."""
    return _normalize_cwe(value)


def first_scalar(value: Any) -> Any:
    """Return the first element of a list/tuple, else the value itself.

    Tool classification ids frequently arrive as single-element lists
    (``["CWE-89"]`` / ``["CVE-2021-3711"]``); this collapses them.
    """
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def load_report(report: Any) -> Any:
    """Coerce a parser input into a Python object.

    Accepts an already-decoded ``dict`` / ``list`` (returned unchanged), or raw
    ``str`` / ``bytes`` JSON text (parsed). Malformed text returns ``None`` so every
    concrete parser can treat "unparseable" and "empty" identically (tolerant, never
    raises) — mirroring the existing ``_parse_*`` helpers.
    """
    if isinstance(report, (bytes, bytearray)):
        report = report.decode("utf-8", "replace")
    if isinstance(report, str):
        text = report.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    return report


def iter_jsonl(report: Any) -> Iterator[dict[str, Any]]:
    """Yield finding dicts from a JSONL-or-list input (Nuclei-style).

    Handles a ``list`` of dicts (yielded as-is), a JSONL ``str``/``bytes`` (one JSON
    object per line — blank and malformed lines skipped), or a single ``dict``.
    """
    if isinstance(report, list):
        for item in report:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(report, dict):
        yield report
        return
    if isinstance(report, (bytes, bytearray)):
        report = report.decode("utf-8", "replace")
    if isinstance(report, str):
        for line in report.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


# ---------------------------------------------------------------------------
# The DefectDojo-style intermediate finding
# ---------------------------------------------------------------------------
@dataclass
class DojoFinding:
    """A tool-agnostic intermediate finding (the DefectDojo normalization shape).

    Every concrete parser emits a list of these; :meth:`to_parsed_vulnerability`
    collapses one down to the canonical :class:`ParsedVulnerability` the persistence
    layer writes, funneling every field without a first-class home into ``evidence``.

    ``severity`` may be a raw tool string (mapped via :func:`normalize_severity`) or a
    pre-resolved :class:`FindingSeverity` (passed through). ``cwe`` may be a bare int
    or an already-``CWE-``-prefixed string. Secret-bearing parsers MUST redact before
    populating this object — never place a plaintext secret in any field, including
    ``raw`` (keep only a non-reversible fingerprint in ``evidence_extra``).
    """

    title: str
    #: Engine label stamped into ``evidence["engine"]`` (e.g. "nuclei"). If left blank
    #: the owning :class:`Parser` stamps its ``tool`` before mapping.
    tool: str = ""
    severity: str | FindingSeverity | None = None
    # Core ParsedVulnerability targets.
    endpoint: str | None = None
    payload: str | None = None
    poc: str | None = None
    cwe: int | str | None = None
    # DefectDojo superset — funneled into evidence (under the stable keys below) when
    # not None, so a runner-swap reproduces the existing evidence shape exactly.
    description: str | None = None
    mitigation: str | None = None
    cve: str | None = None
    cvssv3: str | None = None
    cvssv3_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    file_path: str | None = None
    line: int | None = None
    component_name: str | None = None
    component_version: str | None = None
    references: Any = None
    tags: Any = None
    unique_id_from_tool: str | None = None
    vuln_id_from_tool: str | None = None
    #: Additional endpoints (the first also backfills ``endpoint`` if unset).
    endpoints: list[str] | None = None
    #: Per-tool overflow merged verbatim into evidence (preserves bespoke keys such as
    #: ``template_id`` / ``pkg`` / ``secret_fingerprint`` the runners already emit).
    evidence_extra: dict[str, Any] = field(default_factory=dict)
    #: The (already-sanitized, for secret tools) native item — kept as evidence["raw"]
    #: AND ParsedVulnerability.raw, exactly like the hand-rolled runners.
    raw: Any = None

    #: field -> evidence key. The keys match what the existing runners already write,
    #: so a migrated runner emits an identical evidence dict.
    _EVIDENCE_KEYS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("description", "description"),
        ("mitigation", "mitigation"),
        ("cve", "cve"),
        ("cvssv3", "cvssv3"),
        ("cvssv3_score", "cvssv3_score"),
        ("epss_score", "epss_score"),
        ("epss_percentile", "epss_percentile"),
        ("file_path", "file"),
        ("line", "line"),
        ("component_name", "component_name"),
        ("component_version", "component_version"),
        ("references", "references"),
        ("tags", "tags"),
        ("unique_id_from_tool", "unique_id_from_tool"),
        ("vuln_id_from_tool", "vuln_id_from_tool"),
        ("endpoints", "endpoints"),
    )

    def to_parsed_vulnerability(self) -> ParsedVulnerability:
        """Collapse to the canonical :class:`ParsedVulnerability`.

        Builds evidence as ``{engine} + funneled-superset + evidence_extra + raw`` then
        drops ``None`` values (``raw`` is always retained), matching the existing
        runners' filter. Severity and CWE are normalized on the way out.
        """
        evidence: dict[str, Any] = {"engine": self.tool}
        for attr, key in self._EVIDENCE_KEYS:
            val = getattr(self, attr)
            if val is not None:
                evidence[key] = val
        if self.evidence_extra:
            evidence.update(self.evidence_extra)
        evidence["raw"] = self.raw
        evidence = {k: v for k, v in evidence.items() if v is not None or k == "raw"}

        endpoint = self.endpoint
        if endpoint is None and self.endpoints:
            endpoint = self.endpoints[0]

        return ParsedVulnerability(
            title=str(self.title),
            severity=normalize_severity(self.severity),
            cwe=normalize_cwe(self.cwe),
            endpoint=endpoint,
            payload=self.payload,
            poc=self.poc,
            evidence=evidence,
            raw=self.raw,
        )


# ---------------------------------------------------------------------------
# The parser contract
# ---------------------------------------------------------------------------
class Parser(abc.ABC):
    """Base class for every tool parser.

    Subclasses implement :meth:`parse_findings` (native json -> ``list[DojoFinding]``);
    the shared :meth:`parse` maps those to the canonical ``list[ParsedVulnerability]``
    and stamps the engine label. ``report`` is permissive: an already-decoded
    ``dict``/``list`` or raw ``str``/``bytes`` JSON — concrete parsers use
    :func:`load_report` / :func:`iter_jsonl` to normalize the input and tolerate junk.
    """

    #: Engine label; also the default registry key (see ``parsers/__init__.py``).
    tool: ClassVar[str] = "generic"

    @abc.abstractmethod
    def parse_findings(self, report: dict | list | str | bytes) -> list[DojoFinding]:
        """Translate the tool's native report into intermediate findings."""
        raise NotImplementedError

    def parse(self, report: dict | list | str | bytes) -> list[ParsedVulnerability]:
        """Parse a native report into canonical findings ready for persistence."""
        out: list[ParsedVulnerability] = []
        for finding in self.parse_findings(report):
            if not finding.tool:
                finding.tool = self.tool
            out.append(finding.to_parsed_vulnerability())
        return out
