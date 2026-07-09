"""app.engine.parsers.opengrep — Opengrep -> DojoFinding.

Opengrep is the OSS (LGPL) fork of Semgrep and is output-compatible: identical native
JSON (``{"results": [...]}``) and SARIF. So this is a thin subclass of
:class:`~app.engine.parsers.semgrep.SemgrepParser` that only changes the engine label
to ``opengrep`` — the field maps and the native-JSON/SARIF autodetect are inherited.
Registered under its own key so a run with ``engine="opengrep"`` is labeled correctly.
"""

from __future__ import annotations

from app.engine.parsers.semgrep import SemgrepParser


class OpengrepParser(SemgrepParser):
    tool = "opengrep"
