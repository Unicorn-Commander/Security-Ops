"""Registered-target IMAGE coverage — `app.repositories.targets._covers`.

The gate's second coverage path (`TargetRepository.find_covering` → `_covers`)
matches a concrete image ref against a registered `AuthorizedTarget` of kind
IMAGE. Coverage is tag-agnostic (an image attestation authorizes the asset across
versions, mirroring REPO) with a `/*` namespace wildcard, and fails SAFE. Pinned
here as pure-function tests (no DB): `_covers` only reads `.kind` / `.value`.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.models.target import TargetKind
from app.repositories.targets import _covers, _image_repo


def _t(value: str):
    return SimpleNamespace(kind=TargetKind.IMAGE, value=value)


# ---- _image_repo canonicalization -----------------------------------------
def test_image_repo_defaults_registry_and_library():
    assert _image_repo("nginx:1.21") == ("docker.io", "library/nginx", False)
    assert _image_repo("nginx") == ("docker.io", "library/nginx", False)


def test_image_repo_registry_qualified_strips_tag_and_digest():
    assert _image_repo("ghcr.io/usestrix/strix-sandbox:1.0.0") == (
        "ghcr.io", "usestrix/strix-sandbox", False,
    )
    assert _image_repo("ghcr.io/acme/api@sha256:deadbeef") == ("ghcr.io", "acme/api", False)


def test_image_repo_wildcard_and_port_registry():
    assert _image_repo("ghcr.io/acme/*") == ("ghcr.io", "acme", True)
    assert _image_repo("registry.example.com:5000/team/svc:v2") == (
        "registry.example.com:5000", "team/svc", False,
    )


def test_image_repo_fails_safe():
    assert _image_repo("") == ("", "", False)
    assert _image_repo(None) == ("", "", False)


# ---- _covers IMAGE branch --------------------------------------------------
def test_covers_tag_agnostic_same_repo():
    # A scope authorizing the repo covers any tag of it.
    assert _covers(_t("ghcr.io/acme/app"), "ghcr.io/acme/app:1.2") is True
    assert _covers(_t("ghcr.io/acme/app:1.0"), "ghcr.io/acme/app:9.9") is True


def test_covers_namespace_wildcard():
    assert _covers(_t("ghcr.io/acme/*"), "ghcr.io/acme/api:1.0") is True
    assert _covers(_t("ghcr.io/acme/*"), "ghcr.io/other/api:1.0") is False


def test_covers_docker_hub_library_default():
    assert _covers(_t("docker.io/library/nginx"), "nginx:1.21") is True


def test_covers_rejects_different_registry_or_repo():
    assert _covers(_t("ghcr.io/acme/app"), "docker.io/acme/app:1.2") is False
    assert _covers(_t("ghcr.io/acme/app"), "ghcr.io/acme/other:1.2") is False


def test_covers_image_scope_does_not_cover_unparseable():
    assert _covers(_t("ghcr.io/acme/app"), "") is False
