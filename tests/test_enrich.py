"""EPSS / KEV enrichment is fail-safe."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.engine.enrich as enrich


class _FailingClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        raise RuntimeError("network down")


@pytest.mark.asyncio
async def test_enrich_failure_leaves_findings_untouched(monkeypatch):
    monkeypatch.setattr(enrich.httpx, "AsyncClient", _FailingClient)
    finding = SimpleNamespace(
        title="CVE-2025-1234: Example issue",
        endpoint="pkg@1",
        payload=None,
        poc=None,
        evidence={"engine": "trivy"},
        raw={"VulnerabilityID": "CVE-2025-1234"},
    )
    original = dict(finding.evidence)

    await enrich.enrich_cves([finding])

    assert finding.evidence == original
