"""Console assistant chat backend (spec §6/§7).

Endpoint (under ``/api/v1``; requires SSO + the ``security-ops`` entitlement,
enforced transitively via ``CurrentOrg``):

    POST   /assistant/chat   -> text/event-stream (default) | JSON

The assistant answers questions about the operator's OWN tenant. It reads live,
org-scoped data (the dashboard overview) to ground its answers, and it explains
the authorization gate. It is deliberately **read-only**: it NEVER performs a
write. Instead it proposes write actions to the human as ``suggestions`` — console
deep-links (e.g. ``/engagements?new=1``) the person clicks to act. The model runs
on the internal-direct LiteLLM (Tailscale/LAN, not Cloudflare — long/local calls),
with reasoning/thinking disabled.

Contract:

* Request JSON — ``{"messages": [{"role": "user"|"assistant", "content": str}],
  "stream": bool = true}``.
* Streaming (default) — ``text/event-stream``: ``data: {"delta": "..."}`` chunks,
  then a final ``data: {"done": true, "suggestions": [{"label", "href"}]}``. An
  unexpected failure emits ``data: {"error": str}`` and closes.
* Non-streaming (``stream: false``) — ``{"reply": str, "suggestions": [...]}``.

Degradation: if the LLM is unreachable the endpoint NEVER 500s — it returns a
clear, useful non-LLM message (a grounded summary of the tenant + how the gate
works) with the same suggestions, so the console stays helpful offline.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated, AsyncIterator, Literal

import httpx
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.api.deps import CurrentOrg, DbSession, EntitledUser
from app.core.config import settings
from app.repositories.overview import OverviewRepository

logger = logging.getLogger("secops.api.assistant")

router = APIRouter(tags=["assistant"])

# Ceiling on conversation turns forwarded to the model (defense against oversized
# histories); the newest messages are kept.
_MAX_MESSAGES = 30
_LLM_TIMEOUT = 60.0

_SYSTEM_PROMPT = (
    "You are the Security-Ops console assistant. Security-Ops is an AUTHORIZED "
    "penetration-testing product. Be concise, accurate, and grounded in the tenant "
    "data provided to you.\n\n"
    "THE AUTHORIZATION GATE (explain it when relevant): no scan can touch a target "
    "unless (1) the engagement is ACTIVE and unexpired and inside its rules-of-"
    "engagement time window, (2) the target is in scope and not excluded, and (3) "
    "the target is covered by a registered target whose attestation is currently "
    "valid (not expired/revoked). The gate is server-side and authoritative; the "
    "offensive engine is never trusted to self-limit.\n\n"
    "You can READ the caller's live, org-scoped data to answer concretely, but you "
    "must NEVER perform or promise to perform a write action (creating/activating/"
    "stopping engagements, registering/attesting targets, starting/stopping runs, "
    "handing off findings). When the user needs a write, describe what to do and "
    "rely on the console's suggested deep-links — do not claim you did it."
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(default_factory=list)
    stream: bool = True


class Suggestion(BaseModel):
    label: str
    href: str


# ---------------------------------------------------------------------------
# Live-context grounding + suggestion deep-links
# ---------------------------------------------------------------------------
async def _tenant_context(session, org) -> dict:
    """Read the caller's org-scoped dashboard summary to ground the answer."""
    return await OverviewRepository(session).summary(org.id)


def _context_message(org, summary: dict) -> str:
    """A compact system-context string the model reads to answer concretely."""
    eng = summary.get("engagements", {})
    tgt = summary.get("targets", {})
    runs = summary.get("runs", {})
    fnd = summary.get("findings", {})
    return (
        f"Live tenant data for organization '{org.slug}':\n"
        f"- engagements: total={eng.get('total', 0)} active={eng.get('active', 0)}\n"
        f"- targets: total={tgt.get('total', 0)} attested={tgt.get('attested', 0)}\n"
        f"- runs: total={runs.get('total', 0)} running={runs.get('running', 0)}\n"
        f"- findings: total={fnd.get('total', 0)} open={fnd.get('open', 0)}"
    )


def _suggestions(summary: dict) -> list[Suggestion]:
    """Deep-links the human can click to perform writes the assistant will not.

    Derived from live tenant state so they are contextual, never auto-executed.
    """
    out: list[Suggestion] = [
        Suggestion(label="Create engagement", href="/engagements?new=1"),
        Suggestion(label="Register target", href="/targets?new=1"),
    ]
    targets = summary.get("targets", {})
    if targets.get("total", 0) and targets.get("attested", 0) < targets.get("total", 0):
        out.append(Suggestion(label="Attest a target", href="/targets?attest=1"))
    if summary.get("findings", {}).get("open", 0):
        out.append(Suggestion(label="Review open findings", href="/findings?status=NEW"))
    return out


def _fallback_reply(org, summary: dict) -> str:
    """A useful, LLM-free answer used when the model is unreachable."""
    return (
        "The assistant model is temporarily unreachable, so here is a grounded "
        f"summary instead. Organization '{org.slug}' currently has "
        f"{summary.get('engagements', {}).get('active', 0)} active engagement(s), "
        f"{summary.get('targets', {}).get('attested', 0)} attested target(s), "
        f"{summary.get('runs', {}).get('running', 0)} running run(s), and "
        f"{summary.get('findings', {}).get('open', 0)} open finding(s).\n\n"
        "Remember: a scan is only allowed when the engagement is ACTIVE and "
        "unexpired, the target is in scope and not excluded, and the target has a "
        "currently-valid attestation. Use the suggested links to make changes."
    )


# ---------------------------------------------------------------------------
# LLM transport (internal-direct LiteLLM; thinking OFF). Monkeypatched in tests.
# ---------------------------------------------------------------------------
def _completions_url() -> str:
    return settings.internal_litellm_base_url.rstrip("/") + "/chat/completions"


def _payload(messages: list[dict], *, stream: bool) -> dict:
    """OpenAI-compatible body with thinking disabled (Qwen: always no-think)."""
    return {
        "model": settings.assistant_model,
        "messages": messages,
        "stream": stream,
        "temperature": 0.2,
        # Thinking OFF (Qwen: always no-think). The internal gateway's OpenAI
        # route rejects `reasoning_effort` (UnsupportedParamsError -> 400), so we
        # disable thinking via the Qwen chat-template switch only.
        "chat_template_kwargs": {"enable_thinking": False},
    }


def _headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if settings.internal_litellm_api_key:
        headers["Authorization"] = f"Bearer {settings.internal_litellm_api_key}"
    return headers


async def _llm_complete(messages: list[dict]) -> str:
    """Non-streaming completion → the full reply text. Raises on transport error."""
    async with httpx.AsyncClient(timeout=_LLM_TIMEOUT) as client:
        resp = await client.post(
            _completions_url(), json=_payload(messages, stream=False), headers=_headers()
        )
        resp.raise_for_status()
        data = resp.json()
    return (data["choices"][0]["message"]["content"] or "").strip()


async def _llm_stream(messages: list[dict]) -> AsyncIterator[str]:
    """Streaming completion → text deltas. Raises on transport error (before yield)."""
    async with httpx.AsyncClient(timeout=_LLM_TIMEOUT) as client:
        async with client.stream(
            "POST",
            _completions_url(),
            json=_payload(messages, stream=True),
            headers=_headers(),
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                data = line[len("data:") :].strip()
                if data == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                    delta = chunk["choices"][0]["delta"].get("content")
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue
                if delta:
                    yield delta


def _model_messages(request: ChatRequest, context: str) -> list[dict]:
    """Assemble the model input: system prompt + live context + trimmed history."""
    history = [m.model_dump() for m in request.messages][-_MAX_MESSAGES:]
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "system", "content": context},
        *history,
    ]


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------
@router.post("/assistant/chat")
async def assistant_chat_route(
    request: ChatRequest,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
):
    """Chat with the console assistant (grounded, read-only, gate-aware)."""
    summary = await _tenant_context(session, org)
    context = _context_message(org, summary)
    messages = _model_messages(request, context)
    suggestions = [s.model_dump() for s in _suggestions(summary)]

    if not request.stream:
        try:
            reply = await _llm_complete(messages)
        except Exception:  # noqa: BLE001 - degrade, never 500 on an LLM outage
            logger.warning("assistant: LLM unreachable; serving fallback", exc_info=True)
            reply = _fallback_reply(org, summary)
        return {"reply": reply or _fallback_reply(org, summary), "suggestions": suggestions}

    async def _event_stream() -> AsyncIterator[str]:
        produced = False
        try:
            try:
                async for delta in _llm_stream(messages):
                    produced = True
                    yield _sse({"delta": delta})
            except Exception:  # noqa: BLE001 - LLM outage → graceful fallback text
                logger.warning(
                    "assistant: LLM stream unreachable; serving fallback", exc_info=True
                )
                if not produced:
                    yield _sse({"delta": _fallback_reply(org, summary)})
            yield _sse({"done": True, "suggestions": suggestions})
        except Exception as exc:  # noqa: BLE001 - truly unexpected → error event, no 500
            logger.exception("assistant: unexpected stream error")
            yield _sse({"error": str(exc)})

    return StreamingResponse(_event_stream(), media_type="text/event-stream")
