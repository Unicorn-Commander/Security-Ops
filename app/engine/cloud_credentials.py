"""Prowler's subprocess environment and output redaction (no global env writes)."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import quote, quote_plus

_REDACTED = "[REDACTED]"
_CREDENTIAL_FIELDS = {
    "accesskeyid",
    "awsaccesskeyid",
    "secretaccesskey",
    "awssecretaccesskey",
    "sessiontoken",
    "awssessiontoken",
    "awssecuritytoken",
    "clientsecret",
    "privatekey",
    "password",
    "accesstoken",
    "refreshtoken",
    "authorization",
    "credentials",
}
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_RUNTIME_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")


def isolated_prowler_env(
    credentials: Mapping[str, str], *, home: Path, ambient: Mapping[str, str]
) -> dict[str, str]:
    """Allow only executable/locale settings plus this run's temporary identity.

    A private HOME and disabled SDK config/metadata providers prevent fallback to
    host files, web identity, ECS/container credentials, or instance credentials.
    No app/database/model-gateway/GCP/Azure secrets are inherited by Prowler.
    """
    env = {
        key: value
        for key, value in ambient.items()
        if key in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT"}
    }
    env.update({key: credentials[key] for key in _RUNTIME_KEYS})
    env.update(
        {
            "AWS_DEFAULT_REGION": credentials["AWS_DEFAULT_REGION"],
            "AWS_REGION": credentials["AWS_REGION"],
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "TMPDIR": str(home),
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "BOTO_CONFIG": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    return env


def credential_values(env: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(env[key] for key in _RUNTIME_KEYS if env.get(key))


def scrub_cloud_output(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Redact named credential fields and known session values before persistence.

    Covers nested evidence, list entries, dictionary keys and free-text fields,
    including URL-encoded echoes of the temporary credentials.
    """
    variants = set()
    for secret in secrets:
        if secret:
            variants.update((secret, quote(secret, safe=""), quote_plus(secret)))
    ordered = sorted(variants, key=len, reverse=True)

    def text(raw: str) -> str:
        for secret in ordered:
            raw = raw.replace(secret, _REDACTED)
        return _AWS_KEY.sub(_REDACTED, raw)

    def scrub(item: Any) -> Any:
        if isinstance(item, str):
            return text(item)
        if isinstance(item, dict):
            return {
                text(str(key)): (
                    _REDACTED
                    if re.sub(r"[^a-z0-9]", "", str(key).lower()) in _CREDENTIAL_FIELDS
                    else scrub(child)
                )
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [scrub(child) for child in item]
        return item

    return scrub(value)
