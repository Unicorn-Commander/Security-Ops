"""app.reports — the engagement report assembler (spec §8).

Pure, I/O-light Markdown generation for the client-facing engagement report:
branded header + executive summary + per-finding evidence/PoC/remediation, with
the Strix ``penetration_test_report.md`` appended as the trustworthy (frontier-
verified) full-engine section. The builder functions are deliberately pure — they
accept already-loaded rows and an injected ``generated_at`` timestamp so they are
trivially unit-testable and never touch the clock, the DB, or the network.

The single narrow piece of I/O (reading Strix's report file from disk) lives in
:func:`app.reports.builder.read_strix_report` and is kept separate from the pure
builder. Orchestration (loading rows + supplying the timestamp) is the report
*service* (:mod:`app.services.reports`); the HTTP surface is
``GET /engagements/{id}/report`` in :mod:`app.api.engagements`.

Dependency direction (no cycles): reports -> {core.config, models}. Services and
the API import reports; reports imports nothing from them.
"""

from __future__ import annotations

from app.reports.builder import build_engagement_report, read_strix_report

__all__ = ["build_engagement_report", "read_strix_report"]
