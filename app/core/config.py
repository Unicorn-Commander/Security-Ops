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


settings: Settings = get_settings()
