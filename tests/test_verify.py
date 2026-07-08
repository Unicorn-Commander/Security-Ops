"""Verify pass — verdict parsing + the fail-open gateway call (spec §7).

Pins the tolerant verdict extraction (models wrap JSON in prose/fences) and the
contract that a transport failure NEVER raises — it returns an ``uncertain``
verdict so the sweep finding is preserved. The finding->status promotion logic is
exercised through ``StrixRunner._run_verify_pass`` wiring; here we cover the pure
seam ``app.engine.verify``.
"""

from __future__ import annotations

import pytest

from app.engine import verify as V


def test_parse_verdict_clean_json():
    v = V._parse_verdict('{"verdict":"confirmed","confidence":0.9,"rationale":"clear IDOR"}')
    assert v == {"verdict": "confirmed", "confidence": 0.9, "rationale": "clear IDOR"}


def test_parse_verdict_fenced_and_prose_wrapped():
    text = "Sure, here is my assessment:\n```json\n{\"verdict\": \"refuted\", \"confidence\": 0.8}\n```\nDone."
    v = V._parse_verdict(text)
    assert v["verdict"] == "refuted"
    assert v["confidence"] == 0.8


def test_parse_verdict_clamps_and_defaults():
    # confidence out of range clamps; unknown verdict -> uncertain
    v = V._parse_verdict('{"verdict":"maybe","confidence":5}')
    assert v["verdict"] == "uncertain"
    assert v["confidence"] == 1.0
    # total garbage -> safe uncertain/None
    g = V._parse_verdict("not json at all")
    assert g["verdict"] == "uncertain" and g["confidence"] is None


def test_finding_prompt_omits_missing_fields():
    prompt = V._finding_prompt({"title": "SQLi", "endpoint": None, "evidence": {"description": "d"}})
    assert "Title: SQLi" in prompt
    assert "Endpoint:" not in prompt  # None fields are dropped
    assert "Description: d" in prompt


async def test_verify_call_fail_open(monkeypatch):
    """A transport error must yield an uncertain verdict, never raise."""

    class _Boom:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            raise RuntimeError("gateway down")

    monkeypatch.setattr(V.httpx, "AsyncClient", lambda *a, **k: _Boom())
    out = await V.verify_finding_fields({"title": "x"}, model="gpt-5.4-mini")
    assert out["verdict"] == "uncertain"
    assert out["model"] == "gpt-5.4-mini"
    assert "error" in out


async def test_verify_call_parses_model_response(monkeypatch):
    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": '{"verdict":"confirmed","confidence":0.95}'}}]}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json, headers):
            assert json["model"] == "deepseek-v4-flash"
            return _Resp()

    monkeypatch.setattr(V.httpx, "AsyncClient", lambda *a, **k: _Client())
    out = await V.verify_finding_fields({"title": "IDOR", "endpoint": "/api/Users/1"}, model="deepseek-v4-flash")
    assert out["verdict"] == "confirmed"
    assert out["confidence"] == 0.95
    assert out["model"] == "deepseek-v4-flash"
