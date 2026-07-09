"""Application settings — the single source of truth for configuration.

Everything reads ``from app.core.config import settings``; nothing else in the
app touches ``os.environ`` directly. Backed by pydantic-settings with the
``SECOPS_`` env prefix and an optional ``.env`` file.
"""

import json
from functools import lru_cache
from typing import Annotated, Literal

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
    # Console assistant chat model (spec §7): a logical model name the internal
    # gateway resolves to a local GPU. Reasoning/thinking is disabled at call time.
    assistant_model: str = "strix-qwen3.6-35b"

    # --- Strix runner ----------------------------------------------------
    strix_sandbox_image: str = "ghcr.io/usestrix/strix-sandbox:1.0.0"
    runs_dir: str = "./strix_runs"
    # Hybrid verify pass (spec §7): re-check sweep findings with the profile's
    # stronger `verify` model before the client-facing report. Off by default so a
    # single-model run stays single-pass; the engagement's profile opts in.
    strix_verify_pass: bool = False
    # Fail-safe vulnerability enrichment (EPSS / CISA KEV) for CVE findings.
    enrichment_enabled: bool = True

    # --- Run dispatch (isolated runner sidecar) --------------------------
    # How a gate-cleared PENDING run reaches the Strix subprocess:
    #   "inline" — fire an in-process asyncio worker in the API (dev/tests; default).
    #   "queue"  — enqueue into `run_queue` and let the dedicated `secops-runner`
    #              sidecar claim + execute it. The internet-facing API then never
    #              spawns Strix and never mounts the Docker socket (host root); only
    #              the isolated runner does. See deploy/bigboy/docker-compose.
    run_dispatch_mode: Literal["inline", "queue"] = "inline"
    # Isolated-runner poll cadence (queue mode): how often the sidecar looks for a
    # newly-enqueued PENDING run to claim.
    runner_poll_seconds: float = 3.0
    # Cross-process E-stop: while a scan runs, poll the run's DB status this often
    # and terminate the live Strix subprocess if an operator stopped it (the API's
    # pidfile signal can't cross the container boundary to the runner). 0 disables
    # the watcher — the inline/test path keeps its original single-await behavior.
    runner_stop_poll_seconds: float = 0.0
    # Identifies which runner claimed a queue row (audibility when scaled out).
    runner_id: str = "secops-runner"

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
    # trust a pre-supplied evidence token. NEVER enable in production. (Also bypasses
    # the live STS AssumeRole for the CLOUD_ROLE cloud-account proof.)
    attestation_skip_live_proof: bool = False

    # --- Cloud-account attestation (CLOUD_ROLE possession proof, Prowler) --------
    # The external-ID prefix the operator must require in their cross-account role
    # trust policy; the full challenge is "<prefix>=<target-id>" (unpredictable per
    # target, no server secret). Parity with the DNS/file/header token.
    attestation_cloud_external_id_prefix: str = "security-ops-external-id"
    # Security-Ops' own scanner principal (e.g. an IAM user/role ARN). Shown in the
    # attestation-challenge instructions so the operator knows whom to trust in their
    # role's trust policy. Unset => instructions tell them to ask the operator.
    attestation_scanner_principal_arn: str | None = None
    # Feature switch for the cloud-account possession proof. On by default; unlike
    # break-glass this is NOT admin-only — the proof itself (assuming a role granted
    # with our external ID) is the authorization, exactly like a DNS-TXT proof.
    attestation_allow_cloud_role: bool = True

    # --- Admin-only authorized-operator attestation (break-glass, spec §4) ----
    # These skip the live ownership proof in favor of a RECORDED human authorization.
    # Both are org-ADMIN-only and always audited — accountability is never removed,
    # only the ownership-proof friction. A leaked PAT cannot use them (PATs resolve
    # to OPERATOR, not ADMIN), so god-mode requires an interactive admin SSO session.
    #
    # SELF_ATTESTED: admin authorizes a target on their own responsibility (owned
    # infra / signed engagement). On by default; still admin-gated + justified +
    # time-boxed (attestation_default_ttl_days).
    attestation_allow_self_attest: bool = True
    # BREAK_GLASS: emergency red-team / DFIR authorization of ANY target with a
    # stated justification, no ownership proof. OFF by default — this is the
    # install-time switch to enable god-mode; flip it in the environment when the
    # deployment needs it. Even enabled it stays admin-only, justification-required,
    # short-TTL, and recorded under the dedicated TARGET_BREAK_GLASS audit action.
    attestation_allow_break_glass: bool = False
    # Shorter default lifetime for a break-glass authorization (days). Kept tight so
    # an emergency grant lapses on its own rather than lingering as standing access.
    attestation_break_glass_ttl_days: int = 7

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
