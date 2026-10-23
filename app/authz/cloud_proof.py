"""app.authz.cloud_proof — live authorization proof for CLOUD_ACCOUNT targets (spec §4).

A cloud account (``aws:<account-id>`` / ``gcp:<project-id>`` / ``azure:<subscription>``)
cannot be proven with a DNS-TXT / file-drop / header token the way a domain is — you
do not "publish a token" on an AWS account. The equivalent *possession* proof for
cloud is a **scoped cross-account role grant**: the operator configures a role whose
trust policy (a) trusts Security-Ops' scanner principal and (b) requires the per-target
**external ID** the server generated, and the server proves authorization by actually
**assuming that role** (STS ``AssumeRole`` with our external ID). Being able to assume it
demonstrates the operator granted us scoped access to *this specific account* — the
industry-standard, confused-deputy-safe cross-account pattern (the external ID stops a
third party from tricking us into scanning an account we were not authorized for).

This is the ONE attestation method whose proof is a cloud identity operation rather than
a token lookup, and it is the ONE place the gate's authorization model gained a new
primitive: the recorded evidence is the **assumed-role identity** we obtained (the
AssumedRoleUser ARN + account), not a published string. Everything else about the gate is
unchanged — a CLOUD_ACCOUNT target is still only scannable once it is ATTESTED, unexpired,
in scope, under an ACTIVE engagement.

Design mirrors :mod:`app.authz.proof`:

* the challenge (:func:`cloud_external_id`) is derived from the target's own random
  primary key, so it is unpredictable, stable per target, and needs no server secret;
* verification (:func:`verify_cloud_role`) returns a :class:`CloudProofResult` and never
  raises for a *failed* proof — only for a *misconfigured* one (missing SDK/transport →
  :class:`~app.authz.proof.ProofUnavailable`, surfaced as 503). The caller
  (:func:`app.authz.attestation.attest_target`) turns a non-verified result into a 422 and
  refuses the attestation, so a scan stays impossible until the role actually assumes;
* the live assume-role call is **injectable** (``assume_role`` callable) so the write path
  is fully unit-testable offline, and ``settings.attestation_skip_live_proof`` bypasses the
  live call in air-gapped / test envs exactly like the DNS/HTTP proofs.

Dependency direction (no cycles): cloud_proof -> {core.config, core.errors,
models.target, authz.proof(ProofUnavailable only)}. It never imports authz.gate /
attestation / services / api.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from app.authz.proof import ProofUnavailable
from app.core.config import Settings, settings
from app.models.target import AttestationMethod, AuthorizedTarget, TargetKind

log = logging.getLogger("secops.authz.cloud_proof")

__all__ = [
    "CloudProofResult",
    "cloud_external_id",
    "cloud_instructions",
    "is_cloud_method",
    "parse_cloud_value",
    "verify_cloud_role",
]

# The attestation methods this module verifies (currently just the role-assumption
# proof). Kept as a set for symmetry with app.authz.proof._PROOF_METHODS.
_CLOUD_METHODS = frozenset({AttestationMethod.CLOUD_ROLE})

# The external-ID prefix the operator must set on their role's trust policy; the
# server matches on the full string (prefix=<target-id>).
_EXTERNAL_ID_PREFIX = "security-ops-external-id"

# Supported cloud providers and the value grammar ``<provider>:<account>``.
_PROVIDERS = ("aws", "gcp", "azure")
_CLOUD_VALUE_RE = re.compile(r"^(aws|gcp|azure):([A-Za-z0-9][A-Za-z0-9._\-]{0,255})$", re.IGNORECASE)
# AWS account ids are exactly 12 digits; used to bind the assumed role ARN to the
# attested account so you cannot attest account A by assuming a role in account B.
_AWS_ACCOUNT_RE = re.compile(r"^\d{12}$")


def is_cloud_method(method: AttestationMethod) -> bool:
    return method in _CLOUD_METHODS


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CloudProofResult:
    """Outcome of one cloud role-assumption proof."""

    verified: bool
    method: AttestationMethod
    external_id: str
    role_arn: str
    provider: str
    account: str
    assumed_identity: str | None = None
    observed_account: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def as_evidence(self) -> dict[str, Any]:
        """A JSON-serializable evidence record to persist on the target. The
        ``assumed_identity`` (AssumedRoleUser ARN we obtained) is the accountability
        artifact — it captures WHO we became to scan this account (spec §4)."""
        record = {
            "verified": self.verified,
            "method": self.method.value,
            "external_id": self.external_id,
            "role_arn": self.role_arn,
            "provider": self.provider,
            "account": self.account,
            "assumed_identity": self.assumed_identity,
            "observed_account": self.observed_account,
        }
        if self.detail:
            record["detail"] = self.detail
        return {k: v for k, v in record.items() if v is not None or k in ("verified",)}


# ---------------------------------------------------------------------------
# Challenge (external ID) — derived from the target id, no server secret.
# ---------------------------------------------------------------------------
def cloud_external_id(target: AuthorizedTarget | Any, *, config: Settings | None = None) -> str:
    """The unique external ID the operator must require in their role trust policy.

    Derived from the target's random primary key so it is unpredictable and stable
    across attestation attempts (parity with :func:`app.authz.proof.challenge_token`).
    Format ``security-ops-external-id=<target-id>``; AWS external IDs allow this
    length/charset (2–1224 chars of ``[A-Za-z0-9+=,.@:/-]``).
    """
    prefix = (config or settings).attestation_cloud_external_id_prefix
    tid = getattr(target, "id", target)
    return f"{prefix}={tid}"


def parse_cloud_value(value: str) -> tuple[str, str]:
    """Parse a CLOUD_ACCOUNT value ``<provider>:<account>`` → ``(provider, account)``,
    both lower-cased for the provider. Raises :class:`ValueError` if unparseable."""
    m = _CLOUD_VALUE_RE.match((value or "").strip())
    if not m:
        raise ValueError(
            f"cloud account must be '<provider>:<account>' with provider in {_PROVIDERS}: {value!r}"
        )
    return m.group(1).lower(), m.group(2)


def cloud_instructions(target: AuthorizedTarget, *, config: Settings | None = None) -> dict[str, Any]:
    """Operator instructions for the CLOUD_ROLE proof: the external ID to require, the
    scanner principal to trust, and a copy-paste AWS trust-policy snippet. Returned by
    ``GET /targets/{id}/attestation-challenge`` for CLOUD_ACCOUNT targets (the DNS/HTTP
    instructions do not apply to a cloud account)."""
    cfg = config or settings
    external_id = cloud_external_id(target, config=cfg)
    try:
        provider, account = parse_cloud_value(target.value)
    except ValueError:
        provider, account = "aws", ""
    principal = cfg.attestation_scanner_principal_arn or (
        "<ask your Security-Ops operator for the scanner principal ARN>"
    )
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }
    return {
        "kind": TargetKind.CLOUD_ACCOUNT.value,
        "provider": provider,
        "account": account,
        "target": target.value,
        "external_id": external_id,
        "scanner_principal": principal,
        "method": AttestationMethod.CLOUD_ROLE.value,
        "how": (
            "Create an IAM role in the target account that trusts the Security-Ops "
            "scanner principal and REQUIRES this external ID, grant it a read-only "
            "posture policy (e.g. AWS SecurityAudit), then attest with method "
            "CLOUD_ROLE supplying the role ARN in evidence.role_arn. Security-Ops "
            "proves authorization by assuming the role with the external ID."
        ),
        "evidence_shape": {"role_arn": "arn:aws:iam::<account-id>:role/<role-name>", "region": "us-east-1"},
        "aws_trust_policy": trust_policy,
        "recommended_permissions": ["arn:aws:iam::aws:policy/SecurityAudit"],
    }


# ---------------------------------------------------------------------------
# Live verifier (injectable) — assume the role with our external ID.
# ---------------------------------------------------------------------------
#: Signature of an injectable assume-role call: (role_arn, external_id, region) ->
#: identity dict with at least {"arn": <AssumedRoleUser.Arn>, "account": <id>}.
AssumeRoleFn = Callable[[str, str, str | None], dict[str, Any]]


def _default_assume_role(role_arn: str, external_id: str, region: str | None) -> dict[str, Any]:
    """Assume ``role_arn`` via AWS STS with ``external_id`` (boto3, imported lazily).

    Returns ``{"arn", "account", "user_id"}`` derived from the AssumedRoleUser. Raises
    :class:`ProofUnavailable` (503) if boto3 is missing/misconfigured. A role that
    cannot be assumed (AccessDenied / bad external id) returns ``{}`` — an *unmet*
    proof, not a misconfiguration — so the caller records a non-verified result.
    """
    try:  # pragma: no cover - exercised only in a live AWS deploy
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except Exception:  # pragma: no cover
        raise ProofUnavailable(
            "cloud role verification requires the 'boto3' package",
        ) from None
    try:  # pragma: no cover - network path, live only
        sts = boto3.client("sts", region_name=region or None)
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="security-ops-attestation",
            ExternalId=external_id,
            DurationSeconds=900,
        )
        assumed = resp.get("AssumedRoleUser", {}) or {}
        arn = assumed.get("Arn", "")
        account = arn.split(":")[4] if arn.count(":") >= 4 else ""
        return {"arn": arn, "account": account, "user_id": assumed.get("AssumedRoleId")}
    except ClientError:  # AccessDenied / bad external id
        log.info("cloud_proof.assume_role denied role=%s", role_arn)
        return {}
    except BotoCoreError:  # transport/config; SDK errors may contain credentials
        raise ProofUnavailable("cloud role verification transport error") from None


def _arn_account(role_arn: str) -> str:
    """The account id embedded in an IAM role ARN (``arn:aws:iam::<acct>:role/..``)."""
    parts = (role_arn or "").split(":")
    return parts[4] if len(parts) >= 5 else ""


def verify_cloud_role(
    target: AuthorizedTarget,
    *,
    role_arn: str,
    region: str | None = None,
    assume_role: AssumeRoleFn | None = None,
    config: Settings | None = None,
) -> CloudProofResult:
    """Prove authorization over ``target`` (a CLOUD_ACCOUNT) by assuming ``role_arn``
    with the target's external-ID challenge.

    Verification is TRUE only when every check holds:

    * the target value parses as ``<provider>:<account>``;
    * ``role_arn`` is non-empty and (for AWS) names the SAME account as the target —
      you cannot attest account A with a role in account B;
    * the live ``assume_role`` returns an identity (the operator's trust policy trusts
      our principal AND requires our external ID) whose account matches the target.

    ``settings.attestation_skip_live_proof`` (air-gap / test) records the parameters
    without the live STS call. ``assume_role`` is injectable for offline tests. Raises
    :class:`ProofUnavailable` (503) only if the proof could not be *attempted*.
    """
    cfg = config or settings
    external_id = cloud_external_id(target, config=cfg)
    provider, account = parse_cloud_value(target.value)
    role_arn = (role_arn or "").strip()

    def _result(verified: bool, *, assumed: str | None = None, observed: str | None = None, **detail: Any) -> CloudProofResult:
        return CloudProofResult(
            verified=verified,
            method=AttestationMethod.CLOUD_ROLE,
            external_id=external_id,
            role_arn=role_arn,
            provider=provider,
            account=account,
            assumed_identity=assumed,
            observed_account=observed,
            detail=detail,
        )

    if not role_arn:
        return _result(False, error="missing role_arn")

    # Bind the role to the attested AWS account (12-digit account id in the ARN).
    if provider == "aws" and _AWS_ACCOUNT_RE.match(account):
        arn_account = _arn_account(role_arn)
        if arn_account and arn_account != account:
            return _result(False, observed=arn_account, error="role_arn account does not match target account")

    # Air-gap / test: trust the supplied parameters without a live STS call.
    if cfg.attestation_skip_live_proof:
        return _result(True, assumed=f"skipped:{role_arn}", observed=account, proof="skipped_live_verification")

    identity = (assume_role or _default_assume_role)(role_arn, external_id, region)
    if not identity or not identity.get("arn"):
        return _result(False, error="role could not be assumed with the required external id")

    observed_account = str(identity.get("account") or "")
    # For AWS, the identity we assumed must live in the target account.
    if provider == "aws" and _AWS_ACCOUNT_RE.match(account) and observed_account and observed_account != account:
        return _result(False, assumed=str(identity.get("arn")), observed=observed_account, error="assumed identity is in a different account")

    return _result(True, assumed=str(identity.get("arn")), observed=observed_account or None, user_id=identity.get("user_id"))
