"""app.authz.scope — target normalization + the scope-membership matcher (spec §4).

This is the *real* scope enforcement behind the gate. Two public functions the
gate calls, plus a covering primitive the target registry reuses:

* :func:`normalize_target` — parse a raw target string (``domain`` / ``url`` /
  ``ip``/``cidr`` / ``repo``) into a canonical :class:`NormalizedTarget`. Raises
  :class:`ValueError` on unparseable input (the gate catches that and denies with
  ``target_not_attested``); the covering lookup (``TargetRepository.find_covering``)
  consumes the returned object.
* :func:`target_in_scope` — evaluate a raw target against an engagement's
  ``in_scope`` / ``exclusions`` :class:`~app.schemas.engagement.ScopeRule` lists,
  returning a :class:`ScopeMatch` with independent ``in_scope`` / ``excluded``
  booleans (the gate applies exclusion-wins precedence). NEVER raises — an
  unparseable target is simply "not in scope".
* :func:`target_covers` — the reusable coverage primitive: does an authorized
  entry ``(kind, value)`` cover a target? Kind-aware (a DOMAIN covers its
  subdomains, an IP_RANGE covers member addresses, a URL covers deeper paths on
  the same host, a REPO matches the same owner/repo), and it re-interprets the
  target under the *container's* kind so a URL-shaped target still matches a REPO
  rule. ``TargetRepository.find_covering`` can reuse this to stay DRY with the gate.

Pure + dependency-light on purpose: stdlib only at runtime (``ipaddress`` /
``urllib.parse`` / ``re``), no ORM, no pydantic, no I/O — so the hot-path matcher
is fast, cycle-free, and unit-testable in isolation. ``ScopeRule`` is a duck type
here: anything exposing ``.kind`` (a :class:`~app.models.target.TargetKind`, a
plain string, or ``None``) and ``.value`` (str), or the dict equivalents.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:  # pragma: no cover - typing only; no runtime coupling
    from app.schemas.engagement import EngagementScope, ScopeRule

__all__ = [
    "NormalizedTarget",
    "ScopeMatch",
    "normalize_target",
    "target_in_scope",
    "target_covers",
]

# Canonical kind labels — the string values of app.models.target.TargetKind.
# Kept as literals (not an ORM import) to keep this module ORM-free.
KIND_DOMAIN = "DOMAIN"
KIND_URL = "URL"
KIND_IP_RANGE = "IP_RANGE"
KIND_REPO = "REPO"
KIND_IMAGE = "IMAGE"
KIND_CLOUD_ACCOUNT = "CLOUD_ACCOUNT"

_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
    "ftp": 21,
    "ssh": 22,
}

# Conservative hostname (labels 1-63 of [a-z0-9_-], no leading/trailing hyphen,
# total <= 253). Single-label hosts (localhost, intranet) are allowed; a leading
# "*." wildcard is stripped before validation.
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)"
    r"(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$"
)

# scp-like git remote, e.g. "demo@example.invalid:owner/repo.git".
_SCP_RE = re.compile(r"^(?:git\+)?git@([^:/]+):(.+)$", re.IGNORECASE)

_KIND_ALIASES: dict[str, str] = {
    "DOMAIN": KIND_DOMAIN,
    "HOST": KIND_DOMAIN,
    "HOSTNAME": KIND_DOMAIN,
    "URL": KIND_URL,
    "HTTP": KIND_URL,
    "HTTPS": KIND_URL,
    "WEB": KIND_URL,
    "ENDPOINT": KIND_URL,
    "PATH": KIND_URL,
    "IP_RANGE": KIND_IP_RANGE,
    "IP": KIND_IP_RANGE,
    "IPRANGE": KIND_IP_RANGE,
    "IP-RANGE": KIND_IP_RANGE,
    "CIDR": KIND_IP_RANGE,
    "NETWORK": KIND_IP_RANGE,
    "REPO": KIND_REPO,
    "REPOSITORY": KIND_REPO,
    "GIT": KIND_REPO,
    "IMAGE": KIND_IMAGE,
    "CONTAINER": KIND_IMAGE,
    "DOCKER": KIND_IMAGE,
    "OCI": KIND_IMAGE,
    "IMG": KIND_IMAGE,
    "CLOUD_ACCOUNT": KIND_CLOUD_ACCOUNT,
    "CLOUD-ACCOUNT": KIND_CLOUD_ACCOUNT,
    "CLOUDACCOUNT": KIND_CLOUD_ACCOUNT,
    "CLOUD": KIND_CLOUD_ACCOUNT,
    "ACCOUNT": KIND_CLOUD_ACCOUNT,
    "SUBSCRIPTION": KIND_CLOUD_ACCOUNT,
    "PROJECT": KIND_CLOUD_ACCOUNT,
}

# A cloud-account target: ``<provider>:<account>`` with provider in {aws,gcp,azure}.
# Unambiguous (no URL/repo/image/IP form uses these colon-prefixes), so it is detected
# before the bare-authority parse — otherwise ``aws:123456789012`` would misparse as a
# ``host:port`` domain. The registration ``kind`` is the real authority; this keeps the
# gate's run-target normalization consistent with a registered CLOUD_ACCOUNT row.
_CLOUD_RE = re.compile(r"^(aws|gcp|azure):([A-Za-z0-9][A-Za-z0-9._\-]{0,255})$", re.IGNORECASE)

# Container-image reference grammar (Docker / OCI), used only for IMAGE targets.
# A repository is one or more lowercase path components; a tag is a short
# case-sensitive label; a digest is ``<algorithm>:<hex>`` (>=32 hex, sha256=64).
_IMAGE_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
_REPO_RE = re.compile(rf"^{_IMAGE_NAME_COMPONENT}(?:/{_IMAGE_NAME_COMPONENT})*$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[0-9a-fA-F]{32,}$")
# Canonical default registry for un-qualified Docker Hub references.
_DEFAULT_REGISTRY = "docker.io"


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class NormalizedTarget:
    """A raw target parsed into a canonical, matchable form.

    ``kind`` is one of the ``KIND_*`` labels; ``value`` is the canonical string
    (lower-cased host, default ports dropped, trailing slash stripped, ``.git``
    dropped from repos). ``host`` / ``port`` / ``path`` are populated for the
    kinds that have them (``path`` is ``""`` or a leading-slash path). ``raw`` is
    the original input, retained so covering can re-interpret it under a
    container's kind.
    """

    raw: str
    kind: str
    value: str
    host: str | None = None
    port: int | None = None
    path: str = ""

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value

    def is_covered_by(self, container_kind: Any, container_value: str) -> bool:
        """Whether an authorized entry ``(container_kind, container_value)`` covers self."""
        return target_covers(container_kind, container_value, self)


@dataclass(frozen=True)
class ScopeMatch:
    """The result of :func:`target_in_scope`.

    ``in_scope`` and ``excluded`` are evaluated independently; the gate applies
    the "exclusion wins" precedence (it checks ``excluded`` first). ``matched_rule``
    is the first exclusion rule that matched, else the first in-scope rule.
    """

    in_scope: bool
    excluded: bool
    matched_rule: Any | None = None


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_target(raw: str) -> NormalizedTarget:
    """Parse ``raw`` into a canonical :class:`NormalizedTarget`.

    Detection order: explicit repo syntax (``git@`` / ``ssh://`` / ``git://`` /
    ``.git``) -> UNAMBIGUOUS container image (digest ref, or registry-qualified
    ``registry/name:tag``) -> explicit URL (``scheme://``) -> bare IP / CIDR ->
    bare authority[/path]. Image detection is deliberately conservative (see
    :func:`_is_image_syntax`) so no input that parses as DOMAIN/URL/IP/REPO today
    is reclassified. Raises :class:`ValueError` for empty or unparseable input.
    """
    if raw is None:
        raise ValueError("target is empty")
    s = str(raw).strip()
    if not s:
        raise ValueError("target is empty")

    if _is_repo_syntax(s):
        return _norm_repo(s)
    cloud = _norm_cloud(s)
    if cloud is not None:
        return cloud
    if _is_image_syntax(s):
        return _norm_image(s)
    if "://" in s:
        return _norm_url(s)
    net = _as_ip_network(s)
    if net is not None:
        return NormalizedTarget(raw=s, kind=KIND_IP_RANGE, value=str(net))
    return _norm_bare(s)


def _is_repo_syntax(s: str) -> bool:
    low = s.lower()
    if low.startswith(("git@", "git://", "git+", "ssh://")):
        return True
    core = low.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    return core.endswith(".git")


def _norm_url(s: str) -> NormalizedTarget:
    parts = urlsplit(s)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError(f"URL has no host: {s!r}")
    port = parts.port  # may raise ValueError on a bad port -> propagates
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None
    path = _norm_path(parts.path)
    netloc = host if port is None else f"{host}:{port}"
    value = f"{scheme}://{netloc}{path}" if scheme else f"{netloc}{path}"
    return NormalizedTarget(raw=s, kind=KIND_URL, value=value, host=host, port=port, path=path)


def _norm_bare(s: str) -> NormalizedTarget:
    # Path-only pattern (an exclusion like "/admin" or "/logout/*"). A bare "/"
    # (no host, empty path) is not a usable target/rule -> reject it.
    if s.startswith("/"):
        path = _norm_path(s)
        if not path:
            raise ValueError(f"target has no host: {s!r}")
        return NormalizedTarget(raw=s, kind=KIND_URL, value=path, path=path)

    authority, slash, rest = s.partition("/")
    path = _norm_path("/" + rest) if slash else ""
    host, port = _split_host_port(authority)
    host = host.lower()
    if not _valid_host(host):
        raise ValueError(f"invalid host: {authority!r}")
    netloc = host if port is None else f"{host}:{port}"
    if path:
        return NormalizedTarget(
            raw=s, kind=KIND_URL, value=f"{netloc}{path}", host=host, port=port, path=path
        )
    return NormalizedTarget(raw=s, kind=KIND_DOMAIN, value=netloc, host=host, port=port)


def _norm_repo(s: str) -> NormalizedTarget:
    host, path = _repo_host_path(s)
    if not path:
        raise ValueError(f"unparseable repository: {s!r}")
    value = f"{host}/{path}" if host else path
    return NormalizedTarget(raw=s, kind=KIND_REPO, value=value, host=host or None, path=path)


def _repo_host_path(s: str) -> tuple[str, str]:
    """Extract ``(host, owner/repo)`` from any git remote form, canonicalized
    (lower-cased, credentials stripped, ``.git`` dropped)."""
    low = s.strip()
    scp = _SCP_RE.match(low)
    if scp:
        host = scp.group(1).lower()
        path = scp.group(2)
    elif "://" in low:
        cleaned = low[4:] if low.lower().startswith("git+") else low
        parts = urlsplit(cleaned)
        host = (parts.hostname or "").lower()
        path = parts.path
    else:
        head, _, rest = low.partition("/")
        host = head.lower()
        path = rest
    path = path.strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    return host, path.strip("/").lower()


# ---------------------------------------------------------------------------
# Container images (Docker / OCI references)
# ---------------------------------------------------------------------------
def _looks_like_registry(component: str) -> bool:
    """Docker's registry heuristic: the leading path component is the registry
    iff it contains a ``.`` (domain) or ``:`` (port) or is exactly ``localhost``.
    Otherwise it is part of the repository path (an implicit ``docker.io`` image)."""
    return "." in component or ":" in component or component.lower() == "localhost"


def _split_registry(body: str) -> tuple[str, str]:
    """Split ``registry/remainder`` per the Docker heuristic, defaulting the
    registry to ``docker.io`` when the leading component isn't registry-shaped.
    Returns ``(registry_lowercased, remainder)``."""
    first, slash, rest = body.partition("/")
    if slash and _looks_like_registry(first):
        return first.lower(), rest
    return _DEFAULT_REGISTRY, body


def _parse_image(s: str) -> tuple[str, str, str, str]:
    """Parse ``[registry[:port]/]repository[:tag][@digest]`` into
    ``(registry, repository, tag, digest)``. Registry + repository are lowercased
    (OCI repositories are lowercase by spec); tag case is preserved. Applies the
    ``library/`` namespace default for single-segment Docker Hub images. Raises
    :class:`ValueError` for anything not shaped like an image reference."""
    s = s.strip()
    if not s or "://" in s:
        raise ValueError(f"not an image reference: {s!r}")

    body, sep, digest = s.partition("@")
    digest = digest.strip()
    if sep:
        if not _DIGEST_RE.match(digest):
            raise ValueError(f"invalid image digest: {s!r}")
    else:
        digest = ""

    registry, remainder = _split_registry(body)
    remainder = remainder.strip("/")
    if not remainder:
        raise ValueError(f"image has no repository: {s!r}")

    # A tag colon lives only in the final path segment (registry:port is already split off).
    tag = ""
    slash_idx = remainder.rfind("/")
    last_seg = remainder[slash_idx + 1:]
    if ":" in last_seg:
        name_seg, _, tag = last_seg.rpartition(":")
        if not name_seg or not tag:
            raise ValueError(f"invalid image tag: {s!r}")
        remainder = remainder[: slash_idx + 1] + name_seg

    repository = remainder.strip("/").lower()
    if registry == _DEFAULT_REGISTRY and "/" not in repository:
        repository = "library/" + repository  # docker.io single-name default namespace
    if not _REPO_RE.match(repository):
        raise ValueError(f"invalid image repository: {s!r}")
    if tag and not _TAG_RE.match(tag):
        raise ValueError(f"invalid image tag: {s!r}")
    return registry, repository, tag, digest.lower()


def _has_explicit_registry(s: str) -> bool:
    """Whether ``s`` names a registry explicitly (leading registry-shaped
    component followed by ``/``), as opposed to a bare Docker Hub name."""
    body = s.partition("@")[0]
    first, slash, _rest = body.partition("/")
    return bool(slash) and _looks_like_registry(first)


def _is_image_syntax(s: str) -> bool:
    """UNAMBIGUOUS image detection only — conservative by design so existing
    DOMAIN/URL/IP_RANGE/REPO detection is never disturbed. An input is treated as
    an image only when it (a) carries a content digest (``@sha256:...``), which no
    other target kind uses, or (b) is fully registry-qualified (``registry[/ns]/name``)
    AND pins an explicit ``:tag``. A bare ``name`` or ``name:tag`` (ambiguous with
    ``host:port``) and a registry-qualified path WITHOUT a tag/digest (ambiguous
    with a URL/REPO path) are deliberately NOT classified here — coverage still
    re-derives image identity from the raw string when a container is IMAGE."""
    if "://" in s:
        return False
    try:
        _registry, _repository, tag, digest = _parse_image(s)
    except ValueError:
        return False
    if digest:
        return True
    return bool(tag) and _has_explicit_registry(s)


def _norm_image(s: str) -> NormalizedTarget:
    """Normalize a container-image reference. ``value`` is the canonical
    ``registry/repository[:tag][@digest]``; ``host`` is the registry and ``path``
    is the (tag/digest-stripped) repository, so coverage can compare identity
    without the version pin."""
    registry, repository, tag, digest = _parse_image(s)
    value = f"{registry}/{repository}"
    if tag:
        value += f":{tag}"
    if digest:
        value += f"@{digest}"
    return NormalizedTarget(raw=s, kind=KIND_IMAGE, value=value, host=registry, path=repository)


def _image_identity(s: Any, *, allow_wildcard: bool) -> tuple[str, str, bool] | None:
    """Re-derive ``(registry, repository, is_wildcard)`` from any string, kind-
    agnostically (mirrors ``_repo_host_path`` for REPO). Repository is tag/digest-
    stripped and lowercased. With ``allow_wildcard`` a trailing ``/*`` marks a
    namespace/registry wildcard. Fail-safe: returns ``None`` on any parse failure."""
    try:
        if s is None:
            return None
        text = str(s).strip()
        if not text or "://" in text:
            return None
        if allow_wildcard and text.rstrip("/").endswith("/*"):
            base = text.rstrip("/")[:-2].rstrip("/")  # drop the trailing '/*'
            registry, remainder = _split_registry(base)
            repository = remainder.strip("/").lower()
            if repository and not _REPO_RE.match(repository):
                return None
            return registry, repository, True  # repository may be "" => whole-registry wildcard
        registry, repository, _tag, _digest = _parse_image(text)
        return registry, repository, False
    except Exception:
        return None


def _norm_cloud(s: str) -> "NormalizedTarget | None":
    """Normalize a ``<provider>:<account>`` cloud target, or ``None`` if not one.

    ``value`` is ``<provider-lowercased>:<account>`` (account case preserved — GCP
    project ids and Azure GUIDs are case-sensitive-ish; AWS ids are digits). ``host``
    carries the provider and ``path`` the account, so coverage can compare identity."""
    m = _CLOUD_RE.match(s.strip())
    if not m:
        return None
    provider = m.group(1).lower()
    account = m.group(2)
    value = f"{provider}:{account}"
    return NormalizedTarget(raw=s, kind=KIND_CLOUD_ACCOUNT, value=value, host=provider, path=account)


def _norm_path(p: str | None) -> str:
    """Canonicalize a URL path: collapse ``//``, drop the trailing slash, and map
    the root (``""`` / ``"/"``) to ``""``. Result is ``""`` or a leading-slash path."""
    if not p or p == "/":
        return ""
    p = re.sub(r"/{2,}", "/", p)
    return "/" + p.strip("/")


def _split_host_port(authority: str) -> tuple[str, int | None]:
    if authority.startswith("["):  # bracketed IPv6, e.g. [::1]:8080
        idx = authority.find("]")
        if idx == -1:
            raise ValueError(f"invalid IPv6 authority: {authority!r}")
        host = authority[1:idx]
        rest = authority[idx + 1:]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, None
    if authority.count(":") == 1:
        h, _, p = authority.partition(":")
        if p.isdigit():
            return h, int(p)
    return authority, None


def _valid_host(host: str) -> bool:
    if not host or host == "*":
        return False
    if host.startswith("*."):  # wildcard domain pattern
        host = host[2:]
    return bool(_HOST_RE.match(host))


def _as_ip_network(s: str) -> ipaddress._BaseNetwork | None:
    """Parse ``s`` as an IP address (-> host network) or CIDR, else ``None``."""
    try:
        if "/" in s:
            return ipaddress.ip_network(s, strict=False)
        addr = ipaddress.ip_address(s)
        return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
    except ValueError:
        return None


def _safe_normalize(v: Any) -> NormalizedTarget | None:
    try:
        return normalize_target(v)
    except Exception:
        return None


def _canon_kind(kind: Any) -> str | None:
    if kind is None:
        return None
    k = getattr(kind, "value", kind)  # TargetKind -> its str value
    return _KIND_ALIASES.get(str(k).strip().upper(), str(k).strip().upper())


# ---------------------------------------------------------------------------
# Coverage primitive
# ---------------------------------------------------------------------------
def target_covers(container_kind: Any, container_value: str, target: Any) -> bool:
    """Whether an authorized entry ``(container_kind, container_value)`` covers ``target``.

    ``target`` may be a raw string or a :class:`NormalizedTarget`. ``container_kind``
    may be a :class:`~app.models.target.TargetKind`, a string, or ``None`` (inferred
    from ``container_value``). Kind-aware coverage:

    * DOMAIN ``d`` covers ``d`` and any subdomain (``*.d`` covers subdomains only);
    * URL covers the same host with a path at/under the container path;
    * IP_RANGE covers member addresses / subnets;
    * REPO matches the same ``host/owner/repo`` (re-derived from the target's raw).
    """
    nt = target if isinstance(target, NormalizedTarget) else _safe_normalize(target)
    if nt is None or not container_value:
        return False

    ck = _canon_kind(container_kind)
    if ck is None:
        inferred = _safe_normalize(container_value)
        if inferred is None:
            return False
        ck = inferred.kind
        container_value = inferred.value

    if ck == KIND_DOMAIN:
        return _domain_covers(container_value, nt)
    if ck == KIND_URL:
        return _url_covers(container_value, nt)
    if ck == KIND_IP_RANGE:
        return _ip_covers(container_value, nt)
    if ck == KIND_REPO:
        return _repo_covers(container_value, nt)
    if ck == KIND_IMAGE:
        return _image_covers(container_value, nt)
    if ck == KIND_CLOUD_ACCOUNT:
        return _cloud_covers(container_value, nt)
    return False


def _domain_covers(container_value: str, nt: NormalizedTarget) -> bool:
    dom = _extract_host(container_value)
    if not dom:
        return False
    wildcard = dom.startswith("*.")
    base = (dom[2:] if wildcard else dom).rstrip(".").lower()
    if not base:
        return False
    host = nt.host or (nt.value if nt.kind == KIND_DOMAIN else None)
    if not host:
        return False
    host = host.rstrip(".").lower()
    if wildcard:
        return host.endswith("." + base)
    return host == base or host.endswith("." + base)


def _url_covers(container_value: str, nt: NormalizedTarget) -> bool:
    c = _safe_normalize(container_value)
    if c is None:
        return False
    tpath = nt.path or ""
    if c.host is None:  # path-only container (e.g. exclusion "/admin") -> any host
        return _path_under(tpath, c.path)
    if not nt.host or nt.host.lower() != c.host.lower():
        return False
    if c.port is not None and nt.port is not None and c.port != nt.port:
        return False
    return _path_under(tpath, c.path)


def _path_under(target_path: str, container_path: str) -> bool:
    cp = container_path or ""
    if cp in ("", "/"):
        return True
    if cp.endswith("*"):  # prefix wildcard, e.g. "/admin*"
        return (target_path or "").startswith(cp[:-1].rstrip("/"))
    tp = target_path or ""
    return tp == cp or tp.startswith(cp + "/")


def _ip_covers(container_value: str, nt: NormalizedTarget) -> bool:
    net = _as_ip_network(container_value)
    if net is None:
        return False
    if nt.kind == KIND_IP_RANGE:
        tnet = _as_ip_network(nt.value)
    elif nt.host:
        tnet = _as_ip_network(nt.host)  # host that is an IP literal
    else:
        tnet = None
    if tnet is None or net.version != tnet.version:
        return False
    return tnet.subnet_of(net)


def _repo_covers(container_value: str, nt: NormalizedTarget) -> bool:
    chost, cpath = _repo_host_path(container_value)
    thost, tpath = _repo_host_path(nt.raw)  # re-derive from raw, kind-agnostic
    if not cpath or not tpath:
        return False
    if chost and thost and chost != thost:
        return False
    return cpath == tpath


def _image_covers(container_value: str, nt: NormalizedTarget) -> bool:
    """Whether an IMAGE authorization ``container_value`` covers ``nt``.

    Both sides re-derive ``(registry, repository)`` kind-agnostically from their
    raw strings (mirroring ``_repo_covers``), so a bare ``nginx`` target is covered
    by a ``docker.io/library/nginx`` scope entry even if it normalized as DOMAIN.

    Coverage is TAG-AGNOSTIC (repo-level), matching how REPO coverage ignores the
    ref: an image authorization attests the *asset* (registry + repository) across
    every version, so any ``:tag`` / ``@digest`` on either side is disregarded. A
    trailing ``/*`` on the container repository extends coverage to a whole
    namespace (``ghcr.io/acme/*`` covers ``ghcr.io/acme/api:1.0``). Fail-closed:
    any parse failure yields ``False``."""
    container = _image_identity(container_value, allow_wildcard=True)
    if container is None:
        return False
    creg, crepo, wildcard = container

    target = _image_identity(nt.raw, allow_wildcard=False)
    if target is None:
        return False
    treg, trepo, _ = target

    if creg != treg:
        return False
    if wildcard:
        if crepo == "":  # whole-registry wildcard, e.g. "ghcr.io/*"
            return True
        return trepo == crepo or trepo.startswith(crepo + "/")
    return crepo == trepo


def _cloud_covers(container_value: str, nt: NormalizedTarget) -> bool:
    """Whether a CLOUD_ACCOUNT authorization ``container_value`` covers ``nt``.

    Coverage is EXACT on ``<provider>:<account>`` (an account authorization attests
    exactly that account — never a sibling account), with one deliberate wildcard: a
    whole-provider grant ``<provider>:*`` covers every account of that provider (an org
    that authorized all of its AWS may register ``aws:*``). Fail-closed: a target that
    is not a parseable cloud account is never covered by a cloud rule."""
    cv = (container_value or "").strip()
    cm = _CLOUD_RE.match(cv)
    wildcard = False
    if cm is None:
        # Allow the explicit whole-provider wildcard form ``aws:*`` (not matched by the
        # strict account regex).
        low = cv.lower()
        if low in ("aws:*", "gcp:*", "azure:*"):
            provider, wildcard = low.split(":", 1)[0], True
        else:
            return False
    else:
        provider = cm.group(1).lower()
    target = _norm_cloud(nt.raw) or (nt if nt.kind == KIND_CLOUD_ACCOUNT else None)
    if target is None:
        return False
    tprovider = (target.host or "").lower()
    if provider != tprovider:
        return False
    if wildcard:
        return True
    return cv.lower() == target.value.lower()


def _extract_host(container_value: str) -> str:
    """Host portion of a domain-ish container value (scheme/port/path stripped),
    preserving a leading ``*.`` wildcard."""
    v = container_value.strip()
    if "://" in v:
        try:
            return (urlsplit(v).hostname or "").lower()
        except ValueError:
            return ""
    v = v.split("/", 1)[0]
    if not v:
        return ""
    try:
        host, _port = _split_host_port(v)
    except ValueError:
        return ""
    return host.lower()


# ---------------------------------------------------------------------------
# Scope membership
# ---------------------------------------------------------------------------
def target_in_scope(scope: "EngagementScope | Any", target: str) -> ScopeMatch:
    """Evaluate ``target`` against an engagement ``scope``'s in-scope / exclusion rules.

    Returns a :class:`ScopeMatch` with independent ``in_scope`` / ``excluded``
    booleans (the gate applies exclusion-wins precedence). Never raises: an
    unparseable target yields ``ScopeMatch(in_scope=False, excluded=False)``.
    """
    nt = _safe_normalize(target)
    if nt is None:
        return ScopeMatch(in_scope=False, excluded=False)

    matched_exclusion = _first_match(_rules_of(scope, "exclusions"), nt)
    matched_in_scope = _first_match(_rules_of(scope, "in_scope"), nt)
    return ScopeMatch(
        in_scope=matched_in_scope is not None,
        excluded=matched_exclusion is not None,
        matched_rule=matched_exclusion if matched_exclusion is not None else matched_in_scope,
    )


def _rules_of(scope: Any, name: str) -> list[Any]:
    if scope is None:
        return []
    rules = getattr(scope, name, None)
    if rules is None and isinstance(scope, dict):
        rules = scope.get(name)
    return list(rules) if rules else []


def _first_match(rules: list["ScopeRule | Any"], nt: NormalizedTarget) -> Any | None:
    for rule in rules:
        kind, value = _rule_kv(rule)
        if value and target_covers(kind, value, nt):
            return rule
    return None


def _rule_kv(rule: Any) -> tuple[Any, str | None]:
    if rule is None:
        return (None, None)
    if isinstance(rule, dict):
        kind = rule.get("kind")
        value = rule.get("value")
    else:
        kind = getattr(rule, "kind", None)
        value = getattr(rule, "value", None)
    if value is None:
        return (None, None)
    return (kind, str(value))
