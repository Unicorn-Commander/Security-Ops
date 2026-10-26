"""HTTP contract for the MCP door: 401, discovery, audience, PAT, bypass.

Tool behaviour for a verified PAT stays in ``tests/test_mcp.py`` (``pats_list`` /
``pats_revoke`` go through ``mcp_scope``). This module is the HTTP layer in front
of FastMCP. Fixtures are fictional. Tokens are signed with a test key.
"""

from __future__ import annotations

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.applications import Starlette
from starlette.routing import Mount

from app.core.config import get_settings
from app.mcp.http_guard import McpHttpGuard, configured_public_base
from app.security.pat import create_pat
from tests.conftest import make_org

_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_JWK = json.loads(RSAAlgorithm.to_jwk(_PRIVATE.public_key()))
_PUBLIC_JWK.update({"kid": "test-kid", "alg": "RS256", "use": "sig"})

_INIT = {
    "jsonrpc": "2.0",
    "id": 7,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "fictional-tester", "version": "0"},
    },
}
_LIST = {"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {}}
_ACCEPT = {"accept": "application/json, text/event-stream"}
_ISSUER = "https://auth.test/realms/uchub"


@pytest.fixture
def locked(monkeypatch):
    """Audience enforcement on, bypass off, fictional issuer. No live Keycloak."""
    settings = get_settings()
    monkeypatch.setattr(settings, "auth_bypass", False)
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "keycloak_enabled", True)
    monkeypatch.setattr(settings, "keycloak_enforce_audience", True)
    monkeypatch.setattr(settings, "keycloak_issuer", _ISSUER)
    monkeypatch.setattr(settings, "keycloak_client_id", "security-ops")
    monkeypatch.setattr(settings, "keycloak_audience", None)
    monkeypatch.setattr(settings, "keycloak_expected_audiences", [])
    monkeypatch.setattr(settings, "public_base_url", None)
    monkeypatch.setattr(settings, "mcp_allowed_origins", [])
    monkeypatch.setattr(settings, "entitlement_sku", "security-ops")

    async def jwks(*, force: bool = False):
        return {"keys": [_PUBLIC_JWK]}

    monkeypatch.setattr("app.auth.sso._get_jwks", jwks)
    return settings


def _token(*, aud: str | list[str], azp: str, exp_offset: int = 600) -> str:
    now = int(time.time())
    claims = {
        "iss": _ISSUER,
        "sub": "11111111-1111-1111-1111-111111111111",
        "aud": aud,
        "azp": azp,
        "iat": now,
        "exp": now + exp_offset,
    }
    encoded = jwt.encode(claims, _PRIVATE, algorithm="RS256", headers={"kid": "test-kid"})
    return encoded if isinstance(encoded, str) else encoded.decode("ascii")


async def _stub_app():
    called = {"n": 0}

    async def inner(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] == "http.request" and not message.get("more_body", False):
                break
        called["n"] += 1
        body = b'{"ok":true}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    app = Starlette(routes=[Mount("/mcp", app=McpHttpGuard(inner))])
    return app, called


@pytest.fixture
async def api(locked):
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://security-ops.example") as client:
        yield client


@pytest.fixture
async def door(locked):
    app, called = await _stub_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://security-ops.example") as client:
        yield client, called


def _assert_challenge(response: httpx.Response, *, invalid_token: bool) -> None:
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert 'realm="security-ops-mcp"' in challenge
    assert "resource_metadata=" in challenge
    assert "/.well-known/oauth-protected-resource/mcp/" in challenge
    if invalid_token:
        assert 'error="invalid_token"' in challenge
    else:
        assert "error=" not in challenge
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["code"] == -32001
    assert "message" in body["error"]


async def test_anonymous_initialize_is_401(api):
    response = await api.post("/mcp/", json=_INIT, headers=_ACCEPT)
    _assert_challenge(response, invalid_token=False)
    assert response.json()["id"] == 7
    assert response.headers["content-type"].startswith("application/json")


async def test_anonymous_tools_list_is_401(api):
    response = await api.post("/mcp/", json=_LIST, headers=_ACCEPT)
    _assert_challenge(response, invalid_token=False)
    assert response.json()["id"] == 8
    assert "tools" not in response.text


async def test_presented_bad_bearer_sets_invalid_token(api):
    presented = "not-a-real-credential"
    response = await api.post(
        "/mcp/",
        json=_INIT,
        headers={**_ACCEPT, "authorization": f"Bearer {presented}"},
    )
    _assert_challenge(response, invalid_token=True)
    assert presented not in response.text


async def test_prm_documents_on_both_paths(api):
    paths = (
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource/mcp/",
    )
    for path in paths:
        response = await api.get(path)
        assert response.status_code == 200, path
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["access-control-allow-origin"] == "*"
        assert response.headers["cache-control"] == "public, max-age=3600"
        body = response.json()
        assert set(body) >= {
            "resource",
            "authorization_servers",
            "bearer_methods_supported",
            "scopes_supported",
            "resource_name",
            "resource_documentation",
        }
        assert body["resource"] == "http://security-ops.example/mcp/"
        assert body["authorization_servers"] == [_ISSUER]
        assert body["bearer_methods_supported"] == ["header"]
        assert "security-ops" in body["scopes_supported"]
        options = await api.options(path)
        assert options.status_code == 204, path
        assert options.headers["access-control-allow-origin"] == "*"


async def test_prm_uses_forwarded_host_and_public_base(api, monkeypatch):
    forwarded = await api.get(
        "/.well-known/oauth-protected-resource",
        headers={"x-forwarded-proto": "https", "x-forwarded-host": "secops.example"},
    )
    assert forwarded.json()["resource"] == "https://secops.example/mcp/"

    monkeypatch.setattr(get_settings(), "public_base_url", "https://security-ops.example/mcp")
    pinned = await api.get(
        "/.well-known/oauth-protected-resource/mcp/",
        headers={"x-forwarded-host": "ignored.example"},
    )
    assert pinned.json()["resource"] == "https://security-ops.example/mcp/"
    assert pinned.json()["authorization_servers"] == [_ISSUER]


def test_public_base_with_userinfo_is_ignored(locked, monkeypatch):
    monkeypatch.setattr(
        get_settings(), "public_base_url", "https://user:demo@example.invalid"
    )
    assert configured_public_base() is None


async def test_bare_mcp_redirects_308(api):
    response = await api.post("/mcp", json=_INIT, headers=_ACCEPT, follow_redirects=False)
    assert response.status_code == 308
    assert response.headers["location"] == "/mcp/"
    queried = await api.get("/mcp?x=1", follow_redirects=False)
    assert queried.status_code == 308
    assert queried.headers["location"] == "/mcp/?x=1"


async def test_options_before_auth_and_origin_403(api):
    open_preflight = await api.options("/mcp/")
    assert open_preflight.status_code == 204
    allow = open_preflight.headers["access-control-allow-headers"].lower()
    for name in (
        "authorization",
        "content-type",
        "accept",
        "mcp-session-id",
        "mcp-protocol-version",
        "last-event-id",
    ):
        assert name in allow
    assert "mcp-session-id" in open_preflight.headers["access-control-expose-headers"].lower()

    own = await api.options("/mcp/", headers={"origin": "http://security-ops.example"})
    assert own.status_code == 204
    assert own.headers["access-control-allow-origin"] == "http://security-ops.example"

    secret = "secops_pat_do-not-echo"
    denied = await api.post(
        "/mcp/",
        json=_INIT,
        headers={"origin": "https://evil.example", "authorization": f"Bearer {secret}"},
    )
    assert denied.status_code == 403
    assert secret not in denied.text
    assert "www-authenticate" not in denied.headers
    assert denied.json()["error"] == "origin_not_allowed"


async def test_cookie_and_forwarded_access_token_do_not_authenticate(api):
    cookie = await api.post("/mcp/", json=_LIST, headers={**_ACCEPT, "cookie": "session=fictional"})
    _assert_challenge(cookie, invalid_token=False)
    forwarded = await api.post(
        "/mcp/",
        json=_LIST,
        headers={**_ACCEPT, "x-forwarded-access-token": "forwarded-not-a-mcp-credential"},
    )
    _assert_challenge(forwarded, invalid_token=False)
    assert "forwarded-not-a-mcp-credential" not in forwarded.text


async def test_health_stays_open(api):
    response = await api.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_wrong_audience_is_401(door):
    client, called = door
    token = _token(aud="account", azp="some-other-client")
    response = await client.post(
        "/mcp/",
        json=_INIT,
        headers={**_ACCEPT, "authorization": f"Bearer {token}"},
    )
    _assert_challenge(response, invalid_token=True)
    assert token not in response.text
    assert called["n"] == 0


async def test_azp_or_aud_matching_client_id_passes(door):
    client, called = door
    for aud, azp in (("account", "security-ops"), ("security-ops", "dynamic-client")):
        response = await client.post(
            "/mcp/",
            json=_INIT,
            headers={**_ACCEPT, "authorization": f"Bearer {_token(aud=aud, azp=azp)}"},
        )
        assert response.status_code == 200, (aud, azp)
    assert called["n"] == 2


async def test_expected_audience_list_and_log_only_flag(door, monkeypatch):
    client, called = door
    monkeypatch.setattr(get_settings(), "keycloak_expected_audiences", ["suite-mcp"])
    allowed = await client.post(
        "/mcp/",
        json=_INIT,
        headers={
            **_ACCEPT,
            "authorization": f"Bearer {_token(aud='suite-mcp', azp='https://client.example/register')}",
        },
    )
    assert allowed.status_code == 200

    monkeypatch.setattr(get_settings(), "keycloak_expected_audiences", [])
    monkeypatch.setattr(get_settings(), "keycloak_enforce_audience", False)
    logged = await client.post(
        "/mcp/",
        json=_INIT,
        headers={
            **_ACCEPT,
            "authorization": f"Bearer {_token(aud='account', azp='some-other-client')}",
        },
    )
    assert logged.status_code == 200
    assert called["n"] == 2


async def test_expired_and_bad_issuer_are_401(door):
    client, called = door
    expired = _token(aud="security-ops", azp="security-ops", exp_offset=-120)
    response = await client.post(
        "/mcp/",
        json=_INIT,
        headers={**_ACCEPT, "authorization": f"Bearer {expired}"},
    )
    _assert_challenge(response, invalid_token=True)

    now = int(time.time())
    other = jwt.encode(
        {
            "iss": "https://auth.example/realms/other",
            "sub": "11111111-1111-1111-1111-111111111111",
            "aud": "security-ops",
            "azp": "security-ops",
            "iat": now,
            "exp": now + 600,
        },
        _PRIVATE,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )
    foreign_response = await client.post(
        "/mcp/",
        json=_INIT,
        headers={**_ACCEPT, "authorization": f"Bearer {other}"},
    )
    _assert_challenge(foreign_response, invalid_token=True)
    assert called["n"] == 0


async def test_valid_pat_passes_guard_and_bad_pat_is_401(door, db_session, monkeypatch):
    client, called = door

    async def fake_get_session():
        try:
            yield db_session
        finally:
            await db_session.rollback()

    monkeypatch.setattr("app.mcp.auth.get_session", fake_get_session)
    org = await make_org(db_session, slug="pilot")
    minted = await create_pat(
        db_session,
        "agent-1",
        "fictional-agent",
        ["security-ops"],
        org_slug=org.slug,
        owner_email="demo@example.invalid",
        allowed_scopes=["security-ops"],
    )
    await db_session.commit()

    ok = await client.post(
        "/mcp/",
        json=_LIST,
        headers={**_ACCEPT, "authorization": f"Bearer {minted.plaintext}"},
    )
    assert ok.status_code == 200
    assert called["n"] == 1
    assert minted.plaintext not in ok.text

    bad = "secops_pat_not-a-real-key"
    denied = await client.post(
        "/mcp/",
        json=_LIST,
        headers={**_ACCEPT, "authorization": f"Bearer {bad}"},
    )
    _assert_challenge(denied, invalid_token=True)
    assert bad not in denied.text
    assert called["n"] == 1


async def test_auth_bypass_is_development_only(door, monkeypatch):
    client, called = door
    monkeypatch.setattr(get_settings(), "auth_bypass", True)
    monkeypatch.setattr(get_settings(), "environment", "production")
    blocked = await client.post("/mcp/", json=_INIT, headers=_ACCEPT)
    _assert_challenge(blocked, invalid_token=False)
    assert called["n"] == 0

    monkeypatch.setattr(get_settings(), "environment", "development")
    opened = await client.post("/mcp/", json=_INIT, headers=_ACCEPT)
    assert opened.status_code == 200
    assert called["n"] == 1

    # A presented bad token is not rescued by the bypass.
    still = await client.post(
        "/mcp/",
        json=_INIT,
        headers={**_ACCEPT, "authorization": "Bearer not-a-token"},
    )
    _assert_challenge(still, invalid_token=True)
    assert called["n"] == 1


async def test_mcp_scope_still_rejects_wrong_audience_jwt(locked, db_session):
    """Defence in depth: the tool path rejects a token the HTTP guard would reject."""
    from app.mcp.auth import McpAuthError, mcp_scope, set_current_token

    await make_org(db_session, slug="pilot")
    set_current_token(_token(aud="account", azp="some-other-client"))
    try:
        with pytest.raises(McpAuthError):
            async with mcp_scope(session=db_session):
                pass
    finally:
        set_current_token(None)
