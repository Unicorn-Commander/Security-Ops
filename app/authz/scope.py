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
}


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
    ``.git``) -> explicit URL (``scheme://``) -> bare IP / CIDR -> bare
    authority[/path]. Raises :class:`ValueError` for empty or unparseable input.
    """
    if raw is None:
        raise ValueError("target is empty")
    s = str(raw).strip()
    if not s:
        raise ValueError("target is empty")

    if _is_repo_syntax(s):
        return _norm_repo(s)
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
