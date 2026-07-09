"""TargetRepository — data access for the authorized-target registry
(:class:`app.models.target.AuthorizedTarget`), the gate's source of truth.

Thin async-SQLAlchemy-2.0 data-access layer; repositories NEVER commit (the
caller owns the transaction). Callers:

* ``app.authz.gate._evaluate_scope`` calls :meth:`find_covering` with the
  normalized target to discover the registered target(s) that COVER a concrete
  target, then inspects their attestation itself (this layer does NOT filter on
  attestation — it only resolves coverage).
* ``app.api.targets`` uses :meth:`get` (tenant-checked in the route); the target
  service uses :meth:`list`.

:meth:`find_covering` is intentionally self-contained (it does not import
``app.authz.scope``): repositories are the lowest layer and must not depend on
authz. It re-derives coverage from the row's ``kind`` + ``value`` using stdlib
(``ipaddress`` / ``urllib``), and fails SAFE — any ambiguity resolves to "not
covered" (a denial), never a spurious authorization.

Dependency direction (no cycles): repositories -> {models, db}.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.target import AuthorizedTarget, TargetKind


class TargetRepository:
    """Reads/queries authorized targets. Construct per-request with the session."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, target_id: uuid.UUID) -> AuthorizedTarget | None:
        """Return the target by primary key, or ``None``. Tenant isolation is the
        caller's responsibility (routes compare ``target.org_id``)."""
        return await self.session.get(AuthorizedTarget, target_id)

    async def list(
        self,
        org_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuthorizedTarget], int]:
        """Return ``(items, total)`` for one org's registered targets, newest first."""
        stmt = (
            select(AuthorizedTarget)
            .where(AuthorizedTarget.org_id == org_id)
            .order_by(AuthorizedTarget.created_at.desc(), AuthorizedTarget.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.execute(stmt)).scalars().all())
        total = await self.session.scalar(
            select(func.count())
            .select_from(AuthorizedTarget)
            .where(AuthorizedTarget.org_id == org_id)
        )
        return items, int(total or 0)

    async def find_covering(
        self,
        org_id: uuid.UUID,
        target: Any,
    ) -> list[AuthorizedTarget]:
        """Return every registered target in ``org_id`` that COVERS ``target``.

        ``target`` is the normalized target produced by
        ``app.authz.scope.normalize_target`` (typically a normalized string; a
        richer object is coerced defensively). Coverage per ``kind``:

        * exact ``value`` match (any kind);
        * ``DOMAIN`` — the target host equals the value or is a subdomain of it;
        * ``IP_RANGE`` — the target IP falls inside the CIDR ``value``;
        * ``URL`` / ``REPO`` — the value is a path-boundary prefix of the target.

        Returns a **list** (the gate iterates the result more than once). Coverage
        is evaluated independently of attestation — the gate applies attestation
        validity to the returned rows. Exact matches are ordered first so the
        gate's ``matched_target_id`` points at the most specific covering target.
        """
        needle = _needle(target)
        if not needle:
            return []

        stmt = (
            select(AuthorizedTarget)
            .where(AuthorizedTarget.org_id == org_id)
            .order_by(AuthorizedTarget.created_at.asc(), AuthorizedTarget.id.asc())
        )
        rows = (await self.session.execute(stmt)).scalars().all()

        covering = [t for t in rows if _covers(t, needle)]
        # Stable sort: exact value matches first, registration order preserved within.
        covering.sort(key=lambda t: 0 if _is_exact(t, needle) else 1)
        return covering


# ---------------------------------------------------------------------------
# Coverage helpers — pure, stdlib-only, fail-safe (any error => "not covered").
# ---------------------------------------------------------------------------
def _needle(target: Any) -> str:
    """Coerce the normalized target to a comparable string.

    ``normalize_target`` most likely returns a normalized string; be tolerant of
    a richer object by trying common attributes before falling back to ``str``.
    """
    if target is None:
        return ""
    if isinstance(target, str):
        return target.strip()
    for attr in ("value", "normalized", "host", "target", "name"):
        candidate = getattr(target, attr, None)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return str(target).strip()


def _host_of(value: str) -> str:
    """Extract the lowercased host from a URL / ``host:port`` / bare host string.

    Bare IPv6 literals (``2001:db8::1``) have many colons and no brackets — those
    are returned intact; a port is only stripped from a bracketed IPv6 literal or
    a single-colon ``host:port``.
    """
    text = value.strip()
    netloc = urlsplit(text).netloc if "://" in text else text
    if not netloc:  # e.g. "example.com/path" parses entirely into .path
        netloc = text
    netloc = netloc.rsplit("@", 1)[-1]  # drop any userinfo
    netloc = netloc.split("/", 1)[0]  # drop path (scheme-less inputs)
    if netloc.startswith("["):  # bracketed IPv6 literal, optionally [..]:port
        host = netloc[1:].split("]", 1)[0]
    elif netloc.count(":") == 1:  # host:port (single colon) — not a bare IPv6
        host = netloc.split(":", 1)[0]
    else:  # bare host, or bare IPv6 literal (multiple colons)
        host = netloc
    return host.strip().rstrip(".").lower()


def _ip_of(value: str) -> "ipaddress.IPv4Address | ipaddress.IPv6Address | None":
    text = value.strip()
    try:
        return ipaddress.ip_address(text)  # bare IPv4 / IPv6 literal
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(_host_of(text))  # host inside a URL / host:port
    except ValueError:
        return None


def _image_repo(value: str) -> "tuple[str, str, bool]":
    """Derive ``(registry, repository, wildcard)`` from a container image ref, with
    the tag/digest stripped — the identity an image attestation authorizes.

    Mirrors the canonicalization in ``app.authz.scope`` but kept LOCAL (stdlib only,
    no authz import): repositories are the lowest layer and must not depend on authz,
    exactly like the local ``_host_of`` / ``_ip_of`` helpers. Defaults the registry to
    ``docker.io`` and namespaces a bare Docker Hub name under ``library/`` so ``nginx``
    and ``docker.io/library/nginx`` compare equal. A trailing ``/*`` marks a namespace
    wildcard. Fails SAFE: unparseable input -> ``("", "", False)`` (no coverage).
    """
    try:
        ref = (value or "").strip().lower()
        if not ref:
            return ("", "", False)
        ref = ref.split("@", 1)[0]  # drop any @sha256:... digest
        wildcard = ref.endswith("/*")
        if wildcard:
            ref = ref[:-2]
        first, slash, rest = ref.partition("/")
        # First component is the registry iff it looks like one (has a dot, a :port,
        # or is localhost); otherwise the whole ref is a bare Docker Hub repository.
        if slash and ("." in first or ":" in first or first == "localhost"):
            registry, repository = first, rest
        else:
            registry, repository = "docker.io", ref
        # Strip an image tag: a ':' in the final path segment of the repository.
        if repository and ":" in repository.rsplit("/", 1)[-1]:
            repository = repository.rpartition(":")[0]
        # Default the library/ namespace for single-segment Docker Hub repos.
        if registry == "docker.io" and repository and "/" not in repository:
            repository = "library/" + repository
        if not repository:
            return ("", "", False)
        return (registry, repository, wildcard)
    except Exception:
        return ("", "", False)


def _is_exact(target: AuthorizedTarget, needle: str) -> bool:
    value = (target.value or "").strip()
    return bool(value) and value.lower() == needle.lower()


def _covers(target: AuthorizedTarget, needle: str) -> bool:
    """True if the registered ``target`` covers the ``needle`` string. Fail-safe."""
    try:
        value = (target.value or "").strip()
        if not value or not needle:
            return False
        if value.lower() == needle.lower():
            return True

        kind = target.kind
        if kind == TargetKind.DOMAIN:
            base = value.lower().rstrip(".")
            host = _host_of(needle)
            return bool(host) and (host == base or host.endswith("." + base))
        if kind == TargetKind.IP_RANGE:
            ip = _ip_of(needle)
            if ip is None:
                return False
            try:
                return ip in ipaddress.ip_network(value, strict=False)
            except ValueError:
                return False
        if kind in (TargetKind.URL, TargetKind.REPO):
            base = value.lower().rstrip("/")
            candidate = needle.lower().rstrip("/")
            return candidate == base or candidate.startswith(base + "/")
        if kind == TargetKind.IMAGE:
            # Tag-agnostic, registry+repository identity (parity with REPO: an image
            # attestation authorizes the asset across versions), with a ``/*``
            # namespace wildcard. Same registry AND repository -> covered.
            creg, crepo, wildcard = _image_repo(value)
            nreg, nrepo, _ = _image_repo(needle)
            if not crepo or not nrepo or creg != nreg:
                return False
            if wildcard:
                return nrepo == crepo or nrepo.startswith(crepo + "/")
            return nrepo == crepo
        if kind == TargetKind.CLOUD_ACCOUNT:
            # Exact ``<provider>:<account>`` identity (an account attestation authorizes
            # exactly that account — never a sibling), plus an explicit whole-provider
            # wildcard ``<provider>:*``. Fail-safe: no cross-account coverage.
            base = value.lower()
            cand = needle.lower()
            if base.endswith(":*"):
                return cand.startswith(base[:-1])  # e.g. "aws:" prefix
            return cand == base
        return False
    except Exception:
        # A malformed row must never break the gate — treat as "not covered".
        return False
