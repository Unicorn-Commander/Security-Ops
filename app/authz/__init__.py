"""app.authz — the TARGET authorization gate (spec §4). The product's IP.

AuthorizedTarget attestation + scope-of-engagement enforcement. No scan/run may
name a target that is not covered by an ACTIVE, unexpired, attested scope — and
that boundary is enforced **server-side**, never delegated to the offensive
engine. Every decision is written to the append-only, hash-chained audit log.

Public surface (submodules also import directly, per the shared conventions):

* :func:`app.authz.gate.enforce_scope` / :func:`app.authz.gate.check_scope`
* :func:`app.authz.audit.record_scope_decision`
* scope matching (``app.authz.scope``), attestation (``app.authz.attestation``),
  DTOs (``app.authz.dto``) and 403 errors (``app.authz.errors``).
"""

from __future__ import annotations

from app.authz.audit import record_scope_decision
from app.authz.gate import ALLOWED_CODE, check_scope, enforce_scope

__all__ = [
    "enforce_scope",
    "check_scope",
    "record_scope_decision",
    "ALLOWED_CODE",
]
