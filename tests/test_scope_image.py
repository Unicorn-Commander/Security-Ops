"""Container-image support in the authorization gate's scope matcher.

The Trivy engine scans ``IMAGE`` targets, so ``app.authz.scope`` must (a) normalize
container-image references (``registry/name:tag`` / digest refs) without raising,
(b) cover an image repo across versions (tag-agnostic, REPO-parity) with namespace
wildcards, and — SAFETY-CRITICAL — (c) never reclassify an input that DOMAIN/URL/
IP_RANGE/REPO detection handles today. Image detection is deliberately limited to
UNAMBIGUOUS forms (digest refs, and registry-qualified ``registry/name:tag``); bare
``name`` / ``name:tag`` and registry paths without a tag/digest are left alone.
"""

from __future__ import annotations

import pytest

from app.authz.scope import (
    KIND_DOMAIN,
    KIND_IMAGE,
    KIND_IP_RANGE,
    KIND_REPO,
    KIND_URL,
    NormalizedTarget,
    normalize_target,
    target_covers,
)

_DIGEST = "sha256:" + "a" * 64


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,value,host,path",
    [
        # Bare Docker Hub single-name -> docker.io + library/ namespace default.
        ("nginx", "docker.io/library/nginx", "docker.io", "library/nginx"),
        ("redis:7", "docker.io/library/redis:7", "docker.io", "library/redis"),
        # Registry-qualified with a tag.
        (
            "ghcr.io/usestrix/strix-sandbox:1.0.0",
            "ghcr.io/usestrix/strix-sandbox:1.0.0",
            "ghcr.io",
            "usestrix/strix-sandbox",
        ),
        # Registry with an explicit port + digest.
        (
            f"registry.example.com:5000/team/svc@{_DIGEST}",
            f"registry.example.com:5000/team/svc@{_DIGEST}",
            "registry.example.com:5000",
            "team/svc",
        ),
        # Digest ref against the default registry keeps the library/ default.
        (
            f"redis@{_DIGEST}",
            f"docker.io/library/redis@{_DIGEST}",
            "docker.io",
            "library/redis",
        ),
        # Multi-segment Docker Hub repo (namespace present) -> no library default.
        ("docker.io/acme/api:2.1", "docker.io/acme/api:2.1", "docker.io", "acme/api"),
        # localhost is treated as a registry (has no dot but is the special case).
        ("localhost:5000/app:dev", "localhost:5000/app:dev", "localhost:5000", "app"),
    ],
)
def test_norm_image(raw: str, value: str, host: str, path: str) -> None:
    from app.authz.scope import _norm_image

    nt = _norm_image(raw)
    assert nt.kind == KIND_IMAGE
    assert nt.value == value
    assert nt.host == host
    assert nt.path == path  # tag/digest stripped from path


def test_norm_image_lowercases_registry_but_repo_is_canonical_lower() -> None:
    from app.authz.scope import _norm_image

    nt = _norm_image("GHCR.IO/OwnerName/App:TAG")
    assert nt.host == "ghcr.io"
    assert nt.path == "ownername/app"
    assert nt.value == "ghcr.io/ownername/app:TAG"  # tag case preserved


# ---------------------------------------------------------------------------
# normalize_target classification (IMAGE only for unambiguous forms)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw",
    [
        "ghcr.io/usestrix/strix-sandbox:1.0.0",
        f"registry.example.com:5000/team/svc@{_DIGEST}",
        f"nginx@{_DIGEST}",  # digest is unambiguous even for a bare name
    ],
)
def test_normalize_target_detects_image(raw: str) -> None:
    assert normalize_target(raw).kind == KIND_IMAGE


# ---------------------------------------------------------------------------
# Anti-regression: existing kinds are byte-for-byte unchanged, NEVER IMAGE.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,kind",
    [
        ("example.com:8080", KIND_DOMAIN),
        ("10.0.0.1:443", KIND_DOMAIN),
        ("10.0.0.0/24", KIND_IP_RANGE),
        ("https://app.example.com/path", KIND_URL),
        ("demo@example.invalid:owner/repo.git", KIND_REPO),
        ("https://github.com/owner/repo.git", KIND_REPO),
        ("github.com/owner/repo", KIND_URL),  # registry-shaped host, but no tag -> URL
        ("ghcr.io/owner/app", KIND_URL),  # registry-qualified but NO tag/digest -> URL
        ("nginx", KIND_DOMAIN),  # bare single name is NOT reclassified as an image
    ],
)
def test_normalize_target_does_not_misclassify(raw: str, kind: str) -> None:
    assert normalize_target(raw).kind == kind


def test_ambiguous_bare_name_tag_still_raises_like_today() -> None:
    # "nginx:1.21" is ambiguous with host:port; it must NOT become an image and
    # must keep its existing (fail-closed) ValueError behavior.
    with pytest.raises(ValueError):
        normalize_target("nginx:1.21")


# ---------------------------------------------------------------------------
# Coverage — POSITIVE
# ---------------------------------------------------------------------------
def test_covers_same_repo_across_tags() -> None:
    # Tag-agnostic: an IMAGE authorization attests the repo, not the version.
    assert target_covers(KIND_IMAGE, "ghcr.io/acme/api:1.0", "ghcr.io/acme/api:2.0")
    assert target_covers(KIND_IMAGE, "ghcr.io/acme/api", f"ghcr.io/acme/api@{_DIGEST}")


def test_covers_namespace_wildcard() -> None:
    assert target_covers(KIND_IMAGE, "ghcr.io/acme/*", "ghcr.io/acme/api:1.0")
    assert target_covers(KIND_IMAGE, "ghcr.io/acme/*", "ghcr.io/acme/nested/svc:2")
    # A wildcard does NOT match the namespace prefix as an exact repo of another ns.
    assert not target_covers(KIND_IMAGE, "ghcr.io/acme/*", "ghcr.io/other/api:1")


def test_covers_registry_and_library_defaulting() -> None:
    # Bare "nginx" target (normalizes as DOMAIN) is still covered by the canonical
    # docker.io/library/nginx entry because coverage re-derives image identity.
    assert target_covers(KIND_IMAGE, "docker.io/library/nginx", "nginx")
    # A fully-qualified equivalent is covered too, tag-agnostically.
    assert target_covers(KIND_IMAGE, "docker.io/library/nginx", "docker.io/library/nginx:1.21")
    # "nginx:1.21" is deliberately unparseable (ambiguous with host:port) -> fail-closed.
    assert not target_covers(KIND_IMAGE, "docker.io/library/nginx", "nginx:1.21")


def test_covers_via_normalized_target_object() -> None:
    nt = normalize_target("ghcr.io/acme/api:3.0")
    assert nt.kind == KIND_IMAGE
    assert target_covers(KIND_IMAGE, "ghcr.io/acme/api", nt)


# ---------------------------------------------------------------------------
# Coverage — NEGATIVE
# ---------------------------------------------------------------------------
def test_not_covered_different_registry() -> None:
    assert not target_covers(KIND_IMAGE, "ghcr.io/acme/api", "docker.io/acme/api:1")


def test_not_covered_different_repository() -> None:
    assert not target_covers(KIND_IMAGE, "ghcr.io/acme/api", "ghcr.io/acme/web:1")


def test_cross_kind_isolation() -> None:
    # A DOMAIN scope entry does not authorize an image on a different host...
    assert not target_covers(KIND_DOMAIN, "example.com", "ghcr.io/acme/api:1")
    # ...and an IMAGE entry does not authorize a plain domain target.
    assert not target_covers(KIND_IMAGE, "docker.io/library/nginx", "example.com")
    assert not target_covers(KIND_IMAGE, "ghcr.io/acme/api", "https://ghcr.io/acme/api")


# ---------------------------------------------------------------------------
# Fail-closed: coverage never raises on garbage.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["", "   ", "@@", "reg istry/x", None])
def test_image_coverage_fail_closed(bad) -> None:
    assert target_covers(KIND_IMAGE, "ghcr.io/acme/api", bad) is False
    assert target_covers(KIND_IMAGE, bad, "ghcr.io/acme/api:1") is False


def test_image_covers_accepts_container_alias() -> None:
    # The DOCKER / CONTAINER / OCI / IMG aliases all route to IMAGE coverage.
    for alias in ("CONTAINER", "DOCKER", "OCI", "IMG", "image"):
        assert target_covers(alias, "ghcr.io/acme/api", "ghcr.io/acme/api:9")
