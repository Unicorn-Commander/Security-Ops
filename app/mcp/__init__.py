"""Agent-first MCP surface for Security-Ops.

The MCP server (:mod:`app.mcp.server`) gives an AI agent full parity with the
human console: every operation a person can perform through the HTTP API is
exposed as an MCP tool that reuses the SAME service layer — and therefore the same
authorization gate, entitlement check, and tenant RLS. Auth for every MCP call
(:mod:`app.mcp.auth`) accepts either a durable Personal Access Token
(``secops_pat_…``) or a uchub Keycloak JWT and resolves the identical
:class:`~app.auth.sso.AuthUser` principal the HTTP dependencies would.

The server is mounted on the main FastAPI app at ``/mcp/`` by
``app.main`` (guarded import, like the rest of the optional wiring).
Anonymous HTTP calls are refused with 401 and a protected-resource challenge
before FastMCP lists tools. A call that presents a verifiable bearer still
runs the per-tool scope.
"""
