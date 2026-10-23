"""Mint per-run AWS credentials from an engagement's CLOUD_ROLE-attested target.

Only the role grant and its proof are persisted. STS credentials live in memory
until the Prowler subprocess finishes; they are never attached to an ORM row.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

from sqlalchemy import select

from app.authz.cloud_proof import cloud_external_id, parse_cloud_value
from app.authz.gate import enforce_scope
from app.models.engagement import Engagement
from app.models.target import (
    AttestationMethod,
    AttestationStatus,
    AuthorizedTarget,
    TargetKind,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.sso import AuthUser


class CredentialMintError(RuntimeError):
    """A safe, fixed-message failure: never include SDK responses or exceptions."""


async def mint_prowler_credentials(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    engagement_id: uuid.UUID,
    target_value: str,
    actor: AuthUser | str = "system:prowler-runner",
    run_id: uuid.UUID | None = None,
    assume_role: Callable[[str, str, str], dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Recheck the canonical gate before requesting a 15-minute STS session.

    RLS is also applied by the worker; explicit org predicates keep the minter
    tenant-scoped when used without Postgres (including the offline test suite).
    The caller owns the transaction and must persist gate audit rows on denial.
    """
    engagement = await session.get(Engagement, engagement_id, populate_existing=True)
    if engagement is None or engagement.org_id != org_id:
        raise CredentialMintError("engagement does not belong to the run organization")

    try:
        provider, account = parse_cloud_value(target_value)
    except ValueError:
        raise CredentialMintError("invalid cloud account target") from None
    if provider != "aws":
        raise CredentialMintError(
            "runtime credentials are unsupported for this provider"
        )
    if not re.fullmatch(r"[0-9]{12}", account):
        raise CredentialMintError("invalid AWS account ID")
    target_value = f"aws:{account}"

    await enforce_scope(
        session, engagement_id, target_value, actor=actor, run_id=run_id
    )
    target = await _find_cloud_target(session, org_id, target_value)
    if target is None:
        raise CredentialMintError(
            "no valid CLOUD_ROLE-attested target for this account"
        )

    evidence = target.attestation_evidence or {}
    authorization = evidence.get("cloud_authorization") or {}
    if not isinstance(authorization, dict) or authorization.get("verified") is False:
        raise CredentialMintError("invalid cloud role evidence")
    # The verifier's recorded evidence takes precedence over legacy flat input.
    role_arn = authorization.get("role_arn") or evidence.get("role_arn")
    if not isinstance(role_arn, str) or not re.fullmatch(
        rf"arn:aws:iam::{account}:role/[A-Za-z0-9+=,.@_/-]+", role_arn
    ):
        raise CredentialMintError(
            "attested role ARN does not belong to the target account"
        )
    detail = authorization.get("detail") or {}
    region = authorization.get("region") or evidence.get("region")
    if not region and isinstance(detail, dict):
        region = detail.get("region")
    region = region or "us-east-1"
    if not isinstance(region, str) or not re.fullmatch(r"[a-z0-9-]+", region):
        raise CredentialMintError("invalid AWS region")

    try:
        result = await asyncio.to_thread(
            assume_role or _default_mint_role,
            role_arn,
            cloud_external_id(target),
            region,
        )
    except Exception:
        # Exception text/tracebacks can contain request credentials. Do not chain.
        raise CredentialMintError("STS AssumeRole failed") from None
    return _build_env(result, region=region)


async def _find_cloud_target(
    session: AsyncSession, org_id: uuid.UUID, target_value: str
) -> AuthorizedTarget | None:
    stmt = (
        select(AuthorizedTarget)
        .where(
            AuthorizedTarget.org_id == org_id,
            AuthorizedTarget.value == target_value,
            AuthorizedTarget.kind == TargetKind.CLOUD_ACCOUNT,
            AuthorizedTarget.attestation_status == AttestationStatus.ATTESTED,
            AuthorizedTarget.attestation_method == AttestationMethod.CLOUD_ROLE,
            AuthorizedTarget.revoked_at.is_(None),
            AuthorizedTarget.expires_at.is_(None)
            | (AuthorizedTarget.expires_at > datetime.now(timezone.utc)),
        )
        .execution_options(populate_existing=True)
    )
    return (await session.execute(stmt)).scalars().first()


def _default_mint_role(role_arn: str, external_id: str, region: str) -> dict[str, Any]:
    """Use the runner principal only to assume the target's restricted role."""
    import boto3

    return boto3.client("sts", region_name=region).assume_role(
        RoleArn=role_arn,
        RoleSessionName="security-ops-prowler",
        ExternalId=external_id,
        DurationSeconds=900,
    )


def _build_env(result: dict, *, region: str) -> dict[str, str]:
    credentials = result.get("Credentials") if isinstance(result, dict) else None
    if not isinstance(credentials, dict) or any(
        not isinstance(credentials.get(key), str) or not credentials[key]
        for key in ("AccessKeyId", "SecretAccessKey", "SessionToken")
    ):
        raise CredentialMintError("STS response missing temporary credential fields")
    return {
        "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"],
        "AWS_SESSION_TOKEN": credentials["SessionToken"],
        "AWS_DEFAULT_REGION": region,
        "AWS_REGION": region,
    }
