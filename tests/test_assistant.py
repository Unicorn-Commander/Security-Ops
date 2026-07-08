"""Console assistant chat backend tests.

The route is exercised directly (no HTTP) with the LLM transport monkeypatched, so
the tests are hermetic — they never touch the internal LiteLLM. Guarantees:

* the happy path returns the model's reply plus write-action ``suggestions``
  (deep-links the human clicks — the assistant never writes);
* an LLM outage degrades to a clear, useful non-LLM message rather than raising.
"""

from __future__ import annotations

import app.api.assistant as assistant
from app.api.assistant import ChatMessage, ChatRequest, assistant_chat_route
from app.auth.sso import AuthUser, UserRole
from tests.conftest import make_engagement, make_org


def _user(org_slug: str = "pilot") -> AuthUser:
    return AuthUser(
        id="op-1", email="demo@example.invalid", role=UserRole.OPERATOR, org_slug=org_slug,
        apps=["security-ops"],
    )


async def test_assistant_happy_path_reply_and_suggestions(db_session, monkeypatch):
    org = await make_org(db_session, slug="pilot")
    await make_engagement(db_session, org)  # one ACTIVE engagement in the summary

    captured = {}

    async def _fake_complete(messages):
        captured["messages"] = messages
        return "You have one active engagement."

    monkeypatch.setattr(assistant, "_llm_complete", _fake_complete)

    request = ChatRequest(
        messages=[ChatMessage(role="user", content="What's my status?")],
        stream=False,
    )
    result = await assistant_chat_route(request, db_session, org, _user())

    assert result["reply"] == "You have one active engagement."
    # Suggestions are console deep-links (write actions the assistant proposes only).
    hrefs = {s["href"] for s in result["suggestions"]}
    assert "/engagements?new=1" in hrefs
    assert all(s["href"].startswith("/") for s in result["suggestions"])
    # The model was grounded with a system prompt that explains the gate + live data.
    system_blob = " ".join(
        m["content"] for m in captured["messages"] if m["role"] == "system"
    )
    assert "authorization" in system_blob.lower()
    assert "organization 'pilot'" in system_blob.lower()


async def test_assistant_degrades_when_llm_unreachable(db_session, monkeypatch):
    org = await make_org(db_session, slug="pilot")

    async def _boom(messages):
        raise RuntimeError("litellm unreachable")

    monkeypatch.setattr(assistant, "_llm_complete", _boom)

    request = ChatRequest(
        messages=[ChatMessage(role="user", content="hi")], stream=False
    )
    result = await assistant_chat_route(request, db_session, org, _user())

    # No 500 — a useful, grounded fallback instead, still with suggestions.
    assert "temporarily unreachable" in result["reply"]
    assert result["suggestions"]


async def test_assistant_no_think_payload_disables_reasoning():
    """The model payload always disables thinking (Qwen: no-think, always).

    Thinking is disabled via the Qwen chat-template switch ONLY: the internal
    gateway's OpenAI route rejects ``reasoning_effort`` (UnsupportedParamsError →
    400), so it must NOT be sent.
    """
    body = assistant._payload([{"role": "user", "content": "x"}], stream=False)
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert "reasoning_effort" not in body
