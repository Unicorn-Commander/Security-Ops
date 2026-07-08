"""app.engine.verify — the adversarial verify pass (spec §7 hybrid: sweep→verify).

After the cheap/local SWEEP produces findings, re-check each one with the model
profile's (stronger/different) VERIFY model: confirm or refute it as a REAL,
exploitable vulnerability from the recorded evidence — one LLM call per finding,
NOT a second full Strix scan. The verdict is recorded on the finding
(``evidence["verification"]``); a confident CONFIRM promotes it ``NEW``→``VERIFIED``
and stamps ``verified_by`` with the verify model.

Deliberate asymmetry: a REFUTE never auto-hides a finding. Silently dropping a real
vulnerability is far worse than surfacing a false positive, so a refuted finding
stays ``NEW`` for a human to triage — the verdict only annotates it. The pass is
fail-open per finding: any transport/parse error yields an ``uncertain`` verdict
and leaves the sweep finding untouched, so verification can never lose a finding.

Transport mirrors ``app.api.assistant`` (internal-direct LiteLLM gateway, thinking
OFF). ``verify_finding_fields`` is the single injectable seam tests monkeypatch.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.core.config import settings

log = logging.getLogger("secops.engine.verify")

_VERIFY_TIMEOUT = 60.0
#: A confident confirm at/above this promotes NEW -> VERIFIED.
CONFIRM_THRESHOLD = 0.7

_SYSTEM = (
    "You are a senior application-security reviewer verifying an automated "
    "penetration-test finding. Judge ONLY from the evidence provided whether it is "
    "a REAL, exploitable vulnerability or a likely false positive. Do not invent "
    "facts or assume access you were not shown. Respond with STRICT JSON and nothing "
    'else: {"verdict": "confirmed" | "refuted" | "uncertain", "confidence": '
    '<number between 0 and 1>, "rationale": "<= 2 sentences"}.'
)


def _finding_prompt(fields: dict[str, Any]) -> str:
    ev = fields.get("evidence") or {}
    lines = [
        ("Title", fields.get("title")),
        ("Severity", getattr(fields.get("severity"), "value", fields.get("severity"))),
        ("Endpoint", fields.get("endpoint")),
        ("CWE", fields.get("cwe")),
        ("Description", ev.get("description")),
        ("Proof / PoC", fields.get("poc")),
        ("Payload", fields.get("payload")),
        ("Technical analysis", (ev.get("raw") or {}).get("technical_analysis")),
    ]
    body = "\n".join(f"{k}: {v}" for k, v in lines if v not in (None, ""))
    return "Verify this finding:\n" + body


def _parse_verdict(text: str) -> dict[str, Any]:
    """Tolerant verdict extraction — models sometimes wrap JSON in prose/fences."""
    raw = (text or "").strip()
    start, end = raw.find("{"), raw.rfind("}")
    data: dict[str, Any] = {}
    if start != -1 and end > start:
        try:
            parsed = json.loads(raw[start : end + 1])
            if isinstance(parsed, dict):
                data = parsed
        except json.JSONDecodeError:
            data = {}
    verdict = str(data.get("verdict", "uncertain")).strip().lower()
    if verdict not in ("confirmed", "refuted", "uncertain"):
        verdict = "uncertain"
    confidence: float | None
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence"))))
    except (TypeError, ValueError):
        confidence = None
    rationale = data.get("rationale")
    return {
        "verdict": verdict,
        "confidence": confidence,
        "rationale": str(rationale).strip() if rationale else None,
    }


async def verify_finding_fields(fields: dict[str, Any], *, model: str) -> dict[str, Any]:
    """Call the verify ``model`` for one finding; return a normalized verdict dict.

    Never raises: a transport/HTTP/parse failure returns an ``uncertain`` verdict
    carrying an ``error`` marker, so the caller preserves the sweep finding as-is.
    """
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _finding_prompt(fields)},
        ],
        "temperature": 0.0,
        "max_tokens": 300,
        # Qwen: thinking OFF; harmless for other providers.
        "chat_template_kwargs": {"enable_thinking": False},
    }
    url = settings.internal_litellm_base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if settings.internal_litellm_api_key:
        headers["Authorization"] = f"Bearer {settings.internal_litellm_api_key}"
    try:
        async with httpx.AsyncClient(timeout=_VERIFY_TIMEOUT) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"] or ""
    except Exception as exc:  # noqa: BLE001 - verify must never fail the run
        log.warning("verify.call failed model=%s: %s", model, exc)
        return {"verdict": "uncertain", "confidence": None, "rationale": None, "error": str(exc)[:200], "model": model}
    verdict = _parse_verdict(content)
    verdict["model"] = model
    return verdict
