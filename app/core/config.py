"""Application settings — the single source of truth for configuration.

Everything reads ``from app.core.config import settings``; nothing else in the
app touches ``os.environ`` directly. Backed by pydantic-settings with the
``SECOPS_`` env prefix and an optional ``.env`` file.
"""

import json
from functools import lru_cache
from typing import Annotated

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECOPS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Runtime ---------------------------------------------------------
    environment: str = "production"

    # --- Database --------------------------------------------------------
    # Accepts SECOPS_DATABASE_URL or a bare DATABASE_URL (suite convention).
    database_url: str = Field(
        validation_alias=AliasChoices("SECOPS_DATABASE_URL", "DATABASE_URL"),
    )

    # --- HTTP / CORS -----------------------------------------------------
    # Accepts a JSON array or a comma-separated string in the environment.
    cors_origins: Annotated[list[str], NoDecode] = []

    # --- Operator auth (SSO + entitlement) -------------------------------
    auth_bypass: bool = False  # only honored when environment == "development"
    keycloak_enabled: bool = True
    keycloak_issuer: str
    keycloak_realm: str = "uchub"
    keycloak_client_id: str
    keycloak_audience: str | None = None
    keycloak_jwks_ttl: int = 3600
    entitlement_sku: str = "security-ops"

    # --- Phase-2 model runner --------------------------------------------
    # Spec §7: route internal-direct over Tailscale/LAN, NOT via Cloudflare
    # (long autonomous runs 504/drop through the CF-fronted public gateway).
    internal_litellm_base_url: str = "http://100.126.207.157:4000/v1"
    internal_litellm_api_key: str | None = None

    # --- Strix runner ----------------------------------------------------
    strix_sandbox_image: str = "ghcr.io/usestrix/strix-sandbox:1.0.0"
    runs_dir: str = "./strix_runs"
    # Hybrid verify pass (spec §7): re-check sweep findings with the profile's
    # stronger `verify` model before the client-facing report. Off by default so a
    # single-model run stays single-pass; the engagement's profile opts in.
    strix_verify_pass: bool = False

    # --- Reporting + Brigade hand-off (spec §8) --------------------------
    # Brand wrapper applied around Strix's penetration_test_report.md on export.
    report_brand_name: str = "Security-Ops"
    report_brand_tagline: str = "Autonomous authorized penetration testing — Unicorn Commander"
    # Brigade agent-task intake; unset => hand-off surfaces the honest 501 boundary.
    brigade_base_url: str | None = None
    brigade_api_key: str | None = None

    # --- External-target attestation (spec §4) ---------------------------
    # DNS-TXT record name prefix + the token key the operator must publish/serve.
    attestation_dns_txt_name: str = "_security-ops-authz"
    attestation_file_path: str = "/.well-known/security-ops-authorization.txt"
    attestation_http_header: str = "Strix-Authorization"
    # Live proof HTTP fetch timeout (seconds) and default attestation lifetime (days).
    attestation_http_timeout: float = 10.0
    attestation_default_ttl_days: int = 90
    # Set true in tests / air-gapped envs to skip the live network proof fetch and
    # trust a pre-supplied evidence token. NEVER enable in production.
    attestation_skip_live_proof: bool = False

    # --- Global kill-switch (honored by the authz gate) ------------------
    emergency_stop_all: bool = False

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors_origins(cls, value: object) -> object:
        if value is None or value == "":
            return []
        if isinstance(value, str):
            raw = value.strip()
            if raw.startswith("["):
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    pass
            return [item.strip() for item in raw.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    """Return the cached ``Settings`` singleton."""
    return Settings()  # type: ignore[call-arg]  # populated from env / .env


class _LazySettings:
    """A lazy stand-in for the settings singleton.

    Everything in the app reads ``from app.core.config import settings`` and then
    touches attributes at call time. Deferring construction to first attribute
    access means a bare ``import app.*`` (tests, tooling, ``--help``) never
    requires the full runtime environment to be present — the real
    :class:`Settings` is built (and cached) only when a value is actually read.
    """

    __slots__ = ()

    def __getattr__(self, name: str):
        return getattr(get_settings(), name)

    def __repr__(self) -> str:  # pragma: no cover - debug convenience
        try:
            return repr(get_settings())
        except Exception:  # env not present yet
            return "<Settings (unloaded)>"


#: Lazy settings proxy — resolves to the cached :class:`Settings` on first access.
settings: Settings = _LazySettings()  # type: ignore[assignment]
