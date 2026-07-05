"""app.authz.proof — live ownership-proof verification for external targets (spec §4).

For a target the operator does NOT self-own (an external DOMAIN / URL / IP_RANGE),
attestation-by-checkbox is not enough: the operator must prove control of the
asset before the gate will ever let a scan name it. This module performs that
proof, three ways (spec §4):

* ``DNS_TXT``      — publish a ``TXT`` record at ``<dns-name>.<domain>`` carrying
                     the per-target challenge token;
* ``FILE_DROP``    — serve the challenge token at a well-known path
                     (``/.well-known/security-ops-authorization.txt``);
* ``HTTP_HEADER``  — return the token in a ``Strix-Authorization`` response header.

The challenge token is derived from the target's own random primary key
(:func:`challenge_token`), so it is unpredictable, stable per target, and needs
no server-side secret. Each verifier is **injectable** (a resolver / fetch
callable) so the write path is fully unit-testable offline; the defaults reach
the network via ``dnspython`` (DNS) and ``httpx`` (HTTP), imported lazily so this
module still imports with neither installed.

Verification returns a :class:`ProofResult` (never raises for a *failed* proof —
only for a *misconfigured* one, e.g. no resolver available). The caller
(:func:`app.authz.attestation.attest_target`) turns a non-verified result into a
422 and refuses the attestation; a scan therefore remains impossible until the
proof actually resolves.

Dependency direction (no cycles): authz.proof -> {core.config, core.errors,
models.target}. It never imports authz.gate / attestation / services / api.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

from app.core.config import Settings, settings
from app.core.errors import AppError
from app.models.target import AttestationMethod, AuthorizedTarget, TargetKind

log = logging.getLogger("secops.authz.proof")

__all__ = [
    "ProofResult",
    "ProofUnavailable",
    "challenge_token",
    "proof_instructions",
    "verify_proof",
]

# Methods this module knows how to verify against a live asset.
_PROOF_METHODS = frozenset(
    {AttestationMethod.DNS_TXT, AttestationMethod.FILE_DROP, AttestationMethod.HTTP_HEADER}
)

# The token prefix an operator publishes; the verifier matches on the full string.
_TOKEN_PREFIX = "security-ops-site-verification"


# ---------------------------------------------------------------------------
# Errors + result
# ---------------------------------------------------------------------------
class ProofUnavailable(AppError):
    """The proof could not be *attempted* (missing resolver/dep/transport) — as
    opposed to a proof that was attempted and did not match. Surfaces as 503 so a
    caller can distinguish "we couldn't check" from "the check failed" (422)."""

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message, code="attestation_proof_unavailable", status_code=503, detail=detail)


@dataclass(frozen=True)
class ProofResult:
    """Outcome of one ownership-proof check."""

    verified: bool
    method: AttestationMethod
    token: str
    location: str
    observed: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def as_evidence(self) -> dict[str, Any]:
        """A JSON-serializable evidence record to persist on the target."""
        return {
            "verified": self.verified,
            "method": self.method.value,
            "token": self.token,
            "location": self.location,
            "observed": list(self.observed),
            **({"detail": self.detail} if self.detail else {}),
        }


# ---------------------------------------------------------------------------
# Challenge token — derived from the target's own id (no server secret needed).
# ---------------------------------------------------------------------------
def challenge_token(target: AuthorizedTarget | uuid.UUID | str) -> str:
    """The unique challenge token the operator must publish for ``target``.

    Derived from the target's random primary key, so it is unpredictable and
    stable across attestation attempts. Format: ``security-ops-site-verification=<id>``.
    """
    tid = getattr(target, "id", target)
    return f"{_TOKEN_PREFIX}={tid}"


def _host_of(value: str) -> str:
    """Best-effort host extraction from a domain / URL / host:port value."""
    v = (value or "").strip()
    if "://" in v:
        host = urlsplit(v).hostname or ""
    else:
        host = v.split("/", 1)[0].rsplit("@", 1)[-1]
        if host.startswith("["):
            host = host[1:].split("]", 1)[0]
        elif host.count(":") == 1:
            host = host.split(":", 1)[0]
    return host.strip().rstrip(".").lower()


def _base_url(value: str, host: str) -> str:
    """The ``scheme://host`` to fetch for FILE_DROP / HTTP_HEADER proofs.

    Honors an explicit scheme on a URL target; defaults to https otherwise."""
    v = (value or "").strip()
    if v.lower().startswith(("http://", "https://")):
        parts = urlsplit(v)
        scheme = parts.scheme
        netloc = parts.netloc
        return f"{scheme}://{netloc}"
    return f"https://{host}"


def proof_instructions(target: AuthorizedTarget, *, config: Settings | None = None) -> dict[str, Any]:
    """Human-facing instructions telling the operator exactly what to publish.

    Returned by ``GET /targets/{id}/attestation-challenge`` so the UI can render a
    copy-paste block for each supported external-proof method.
    """
    cfg = config or settings
    token = challenge_token(target)
    host = _host_of(target.value)
    base = _base_url(target.value, host)
    dns_name = f"{cfg.attestation_dns_txt_name}.{host}"
    return {
        "token": token,
        "target": target.value,
        "methods": {
            AttestationMethod.DNS_TXT.value: {
                "record_type": "TXT",
                "name": dns_name,
                "value": token,
                "how": f"Publish a TXT record at {dns_name!r} whose value is the token.",
            },
            AttestationMethod.FILE_DROP.value: {
                "url": f"{base}{cfg.attestation_file_path}",
                "body": token,
                "how": f"Serve the token as the body of {base}{cfg.attestation_file_path}.",
            },
            AttestationMethod.HTTP_HEADER.value: {
                "url": base,
                "header": cfg.attestation_http_header,
                "value": token,
                "how": f"Return the token in the {cfg.attestation_http_header!r} response header from {base}.",
            },
        },
    }


# ---------------------------------------------------------------------------
# Default (live) resolver + fetcher — lazily import optional deps.
# ---------------------------------------------------------------------------
DnsResolver = Callable[[str], Iterable[str]]
HttpFetch = Callable[[str], "tuple[str, dict[str, str]]"]  # url -> (body, headers)


def _default_dns_resolver(name: str) -> list[str]:
    """Resolve TXT records for ``name`` via dnspython (imported lazily)."""
    try:
        import dns.resolver  # type: ignore
    except Exception as exc:  # pragma: no cover - exercised only without the dep
        raise ProofUnavailable(
            "DNS TXT verification requires the 'dnspython' package",
            detail={"error": str(exc)},
        ) from exc
    try:
        answers = dns.resolver.resolve(name, "TXT")
    except Exception as exc:
        # NXDOMAIN / no-answer / timeout => an *unmet* proof, not a misconfig.
        log.info("proof.dns.no-answer name=%s: %s", name, exc)
        return []
    records: list[str] = []
    for rdata in answers:
        # Each TXT rdata is one or more quoted strings; join them.
        strings = getattr(rdata, "strings", None)
        if strings:
            records.append(b"".join(strings).decode("utf-8", "replace"))
        else:
            records.append(str(rdata).strip('"'))
    return records


def _default_http_fetch(url: str, *, config: Settings | None = None) -> tuple[str, dict[str, str]]:
    """Fetch ``url`` and return ``(body, headers)`` (headers lower-cased) via httpx."""
    cfg = config or settings
    try:
        import httpx  # imported here so the module loads without httpx present
    except Exception as exc:  # pragma: no cover
        raise ProofUnavailable("HTTP verification requires 'httpx'", detail={"error": str(exc)}) from exc
    try:
        resp = httpx.get(url, timeout=cfg.attestation_http_timeout, follow_redirects=True)
    except Exception as exc:
        log.info("proof.http.fetch-failed url=%s: %s", url, exc)
        return ("", {})
    headers = {k.lower(): v for k, v in resp.headers.items()}
    return (resp.text or "", headers)


# ---------------------------------------------------------------------------
# The verifiers (pure given their injected resolver/fetch)
# ---------------------------------------------------------------------------
def _matches(token: str, values: Iterable[str]) -> list[str]:
    """Return the observed values that carry ``token`` (exact or substring)."""
    hits: list[str] = []
    for v in values:
        if v and token in v:
            hits.append(v.strip())
    return hits


def verify_dns_txt(
    target: AuthorizedTarget,
    *,
    resolver: DnsResolver | None = None,
    config: Settings | None = None,
) -> ProofResult:
    cfg = config or settings
    token = challenge_token(target)
    host = _host_of(target.value)
    name = f"{cfg.attestation_dns_txt_name}.{host}"
    resolve = resolver or _default_dns_resolver
    records = list(resolve(name))
    hits = _matches(token, records)
    return ProofResult(
        verified=bool(hits),
        method=AttestationMethod.DNS_TXT,
        token=token,
        location=name,
        observed=records,
        detail={"matched": hits},
    )


def verify_file_drop(
    target: AuthorizedTarget,
    *,
    fetch: HttpFetch | None = None,
    config: Settings | None = None,
) -> ProofResult:
    cfg = config or settings
    token = challenge_token(target)
    host = _host_of(target.value)
    url = f"{_base_url(target.value, host)}{cfg.attestation_file_path}"
    body, _headers = (fetch or (lambda u: _default_http_fetch(u, config=cfg)))(url)
    hits = _matches(token, [body])
    return ProofResult(
        verified=bool(hits),
        method=AttestationMethod.FILE_DROP,
        token=token,
        location=url,
        observed=[body[:512]] if body else [],
        detail={"matched": bool(hits)},
    )


def verify_http_header(
    target: AuthorizedTarget,
    *,
    fetch: HttpFetch | None = None,
    config: Settings | None = None,
) -> ProofResult:
    cfg = config or settings
    token = challenge_token(target)
    host = _host_of(target.value)
    url = _base_url(target.value, host)
    header_name = cfg.attestation_http_header.lower()
    _body, headers = (fetch or (lambda u: _default_http_fetch(u, config=cfg)))(url)
    observed = [headers.get(header_name, "")] if headers.get(header_name) else []
    hits = _matches(token, observed)
    return ProofResult(
        verified=bool(hits),
        method=AttestationMethod.HTTP_HEADER,
        token=token,
        location=f"{url} [{cfg.attestation_http_header}]",
        observed=observed,
        detail={"matched": bool(hits)},
    )


_VERIFIERS = {
    AttestationMethod.DNS_TXT: verify_dns_txt,
    AttestationMethod.FILE_DROP: verify_file_drop,
    AttestationMethod.HTTP_HEADER: verify_http_header,
}


def is_proof_method(method: AttestationMethod) -> bool:
    return method in _PROOF_METHODS


def verify_proof(
    target: AuthorizedTarget,
    method: AttestationMethod,
    *,
    resolver: DnsResolver | None = None,
    fetch: HttpFetch | None = None,
    config: Settings | None = None,
) -> ProofResult:
    """Verify the ownership proof for ``target`` under ``method`` against the live asset.

    Dispatches to the DNS / file / header verifier. ``resolver`` / ``fetch`` are
    injectable for tests. Returns a :class:`ProofResult` — check ``.verified``.
    Raises :class:`ProofUnavailable` only when the proof could not be attempted
    (missing dependency / transport), never for a proof that simply did not match.
    """
    verifier = _VERIFIERS.get(method)
    if verifier is None:
        raise ProofUnavailable(f"no live verifier for method {method.value}")
    if method is AttestationMethod.DNS_TXT:
        return verifier(target, resolver=resolver, config=config)
    return verifier(target, fetch=fetch, config=config)
