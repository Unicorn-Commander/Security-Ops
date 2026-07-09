"""app.engine.parsers — the DefectDojo-style, tool-agnostic finding normalizer.

The highest-leverage enabler in the multi-engine roadmap: it turns adding a scanner
into "wire a CLI + point at a parser" instead of "hand-write a JSON->Finding
normalizer". Each concrete parser translates one tool's NATIVE json into a list of
:class:`~app.engine.parsers.base.DojoFinding` (the DefectDojo superset intermediate),
and the shared base collapses those to ``list[ParsedVulnerability]`` — the canonical
internal finding shape ``StrixRunner._store_findings`` persists.

Public surface:

* :func:`get_parser` — look up a parser instance by tool/engine name (case-insensitive,
  alias-aware); returns ``None`` for an unknown tool so callers can fall back to
  ``get_parser("generic")``.
* :data:`PARSERS` — the name -> parser-instance registry.

Provenance: the architecture (one small parser per tool feeding a common normalizer)
and the intermediate field superset are modeled on DefectDojo (BSD-3-Clause); this is
an original re-implementation of that approach, not a code port. See
``app/engine/parsers/base.py`` for the full note + the runner migration path.

Dependency direction: parsers -> {engine.strix_runner, engine.gitleaks_runner,
engine.trivy_runner}. The runners do NOT import parsers, so there is no cycle — a
runner opts into the normalizer by calling ``get_parser(...)`` in ``_build_result``.
"""

from __future__ import annotations

from app.engine.parsers.base import DojoFinding, Parser, ParsedVulnerability
from app.engine.parsers.generic import GenericParser
from app.engine.parsers.gitleaks import GitleaksParser
from app.engine.parsers.nuclei import NucleiParser
from app.engine.parsers.opengrep import OpengrepParser
from app.engine.parsers.sarif import SarifParser
from app.engine.parsers.semgrep import SemgrepParser
from app.engine.parsers.trivy import TrivyParser
from app.engine.parsers.zap import ZapParser

#: tool/engine name -> parser instance. Parsers are stateless, so a shared singleton
#: per tool is safe. Aliases (``trivy-secrets`` -> trivy, ``opengrep`` -> its own
#: labeled parser) let a run's engine string map straight through.
PARSERS: dict[str, Parser] = {
    "nuclei": NucleiParser(),
    "trivy": TrivyParser(),
    "trivy-secrets": TrivyParser(),  # trivy's secret results ride the same report
    "gitleaks": GitleaksParser(),
    "sarif": SarifParser(),
    "semgrep": SemgrepParser(),
    "opengrep": OpengrepParser(),
    "zap": ZapParser(),
    "owasp-zap": ZapParser(),
    "generic": GenericParser(),
}


def get_parser(tool: str) -> Parser | None:
    """Return the parser for ``tool`` (case-insensitive), or ``None`` if unknown.

    An unknown tool returns ``None`` rather than raising, so a caller can decide to
    fall back to the permissive ``get_parser("generic")`` parser.
    """
    if not tool:
        return None
    return PARSERS.get(tool.strip().lower())


__all__ = [
    "PARSERS",
    "get_parser",
    "Parser",
    "DojoFinding",
    "ParsedVulnerability",
    "GenericParser",
    "GitleaksParser",
    "NucleiParser",
    "OpengrepParser",
    "SarifParser",
    "SemgrepParser",
    "TrivyParser",
    "ZapParser",
]
