"""Data access and idempotent Center Deep finding import.

The import path intentionally does not call ``start_run`` or any engagement
activation/attestation service.  A Center Deep delivery is a completed external
watch observation, not a Security-Ops scan, so the synthetic engagement and run
are written directly.  The normal findings repository is still used so its
fingerprint deduplication and ``also_found_by`` behavior remain canonical.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, ValidationAppError
from app.db.rls import clear_org_context, set_org_context
from app.models.engagement import Engagement, EngagementStatus
from app.models.finding import FindingSeverity, FindingStatus
from app.models.ingest_source import IngestSource
from app.models.organization import Organization
from app.models.run import Run, RunMode, RunStatus
from app.repositories.findings import FindingRepository
from app.schemas.engagement import DEFAULT_MODEL_PROFILE
from app.schemas.ingest import CenterDeepWebhook

EXTERNAL_ENGAGEMENT_NAME = "External watch: Center Deep Research"
CENTER_DEEP_KIND = "center-deep"
WEBHOOK_TOLERANCE_SECONDS = 300
WEBHOOK_DUPLICATE_WINDOW = timedelta(hours=24)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _mint_secret() -> str:
    """Mint the Standard Webhooks ``whsec_`` form with 32 random bytes."""

    return "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _webhook_error(message: str, *, code: str, status_code: int) -> AppError:
    """Build a non-sensitive webhook authentication/timestamp error."""

    return AppError(message, code=code, status_code=status_code)


def _secret_key(secret: str) -> bytes | None:
    """Apply both key derivations from CONTRACT-webhook.md."""

    if secret.startswith("whsec_"):
        try:
            return base64.b64decode(secret[len("whsec_") :], validate=True)
        except (ValueError, base64.binascii.Error):
            return None
    return secret.encode("utf-8")


def _signature_values(header: str | None) -> list[str]:
    """Return only v1 signature values from a Standard Webhooks header."""

    values: list[str] = []
    for item in (header or "").split():
        version, separator, value = item.partition(",")
        if version == "v1" and separator and value:
            values.append(value)
    return values


def _fingerprint(*parts: object) -> str:
    """Fingerprint Center Deep identity tuples with stable normalization."""

    material = "|".join(
        "" if value is None else " ".join(str(value).strip().lower().split())
        for value in parts
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _as_aware_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class IngestSourceRepository:
    """CRUD for organization-scoped external ingest sources."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        org_id: uuid.UUID,
        name: str,
        created_by: str,
        kind: str = CENTER_DEEP_KIND,
    ) -> tuple[IngestSource, str]:
        """Create a source and return its row plus the one-time plaintext secret."""

        plaintext = _mint_secret()
        source = IngestSource(
            org_id=org_id,
            name=name,
            kind=kind,
            secret=plaintext,
            created_by=created_by,
        )
        self.session.add(source)
        await self.session.flush()
        return source, plaintext

    async def list_for_org(self, org_id: uuid.UUID) -> list[IngestSource]:
        stmt = (
            select(IngestSource)
            .where(IngestSource.org_id == org_id)
            .order_by(IngestSource.created_at.desc(), IngestSource.id.desc())
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def get_for_org(
        self, source_id: uuid.UUID, org_id: uuid.UUID
    ) -> IngestSource | None:
        stmt = select(IngestSource).where(
            IngestSource.id == source_id,
            IngestSource.org_id == org_id,
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def rotate(
        self, source: IngestSource, *, rotated_at: datetime | None = None
    ) -> str:
        plaintext = _mint_secret()
        source.secret = plaintext
        source.rotated_at = rotated_at or _utcnow()
        await self.session.flush()
        return plaintext

    async def disable(
        self, source: IngestSource, *, disabled_at: datetime | None = None
    ) -> IngestSource:
        if source.disabled_at is None:
            source.disabled_at = disabled_at or _utcnow()
            await self.session.flush()
        return source


# Short alias for callers that treat source administration as the ingest repo.
IngestRepository = IngestSourceRepository


def _delivery_now(now: datetime | None) -> datetime:
    current = now or _utcnow()
    return current if current.tzinfo is not None else current.replace(tzinfo=UTC)


def _parse_timestamp(timestamp: str | None, *, now_epoch: float) -> int:
    try:
        value = int(str(timestamp))
    except (TypeError, ValueError) as exc:
        raise _webhook_error(
            "invalid webhook timestamp",
            code="invalid_webhook_timestamp",
            status_code=401,
        ) from exc
    if abs(now_epoch - value) > WEBHOOK_TOLERANCE_SECONDS:
        raise _webhook_error(
            "webhook timestamp is outside the accepted window",
            code="stale_webhook",
            status_code=409,
        )
    return value


async def _matching_source(
    session: AsyncSession,
    *,
    webhook_id: str,
    timestamp: str,
    signature_header: str | None,
    raw_body: bytes,
) -> IngestSource | None:
    """Try every enabled Center Deep source without short-circuiting matches."""

    signatures = _signature_values(signature_header)
    if not signatures:
        return None

    matched: IngestSource | None = None
    signed = f"{webhook_id}.{timestamp}.".encode("utf-8") + raw_body
    org_ids = list((await session.execute(select(Organization.id))).scalars().all())
    for org_id in org_ids:
        await set_org_context(session, org_id)
        stmt = select(IngestSource).where(
            IngestSource.kind == CENTER_DEEP_KIND,
            IngestSource.disabled_at.is_(None),
        )
        sources = list((await session.execute(stmt)).scalars().all())
        for source in sources:
            key = _secret_key(source.secret)
            if key is None:
                continue
            expected = base64.b64encode(
                hmac.new(key, signed, hashlib.sha256).digest()
            ).decode("ascii")
            for supplied in signatures:
                # Do not stop after the first match.  Source enumeration is tiny
                # and this keeps matching work uniform across enabled credentials.
                equal = hmac.compare_digest(expected, supplied)
                if equal and matched is None:
                    matched = source
    if matched is None:
        await clear_org_context(session)
    else:
        await set_org_context(session, matched.org_id)
    return matched


def _is_recent_duplicate(source: IngestSource, webhook_id: str, now: datetime) -> bool:
    last = _as_aware_utc(source.last_delivery_at)
    if source.last_webhook_id != webhook_id or last is None:
        return False
    return abs((now - last).total_seconds()) <= WEBHOOK_DUPLICATE_WINDOW.total_seconds()


async def _ensure_external_engagement(
    session: AsyncSession, *, org_id: uuid.UUID, now: datetime
) -> Engagement:
    stmt = select(Engagement).where(
        Engagement.org_id == org_id,
        Engagement.name == EXTERNAL_ENGAGEMENT_NAME,
    )
    engagement = (await session.execute(stmt)).scalars().first()
    if engagement is None:
        engagement = Engagement(
            org_id=org_id,
            name=EXTERNAL_ENGAGEMENT_NAME,
            status=EngagementStatus.ACTIVE,
            scope={"external": True, "source": CENTER_DEEP_KIND},
            rules_of_engagement={"imported": True},
            model_profile=DEFAULT_MODEL_PROFILE,
            created_by="center-deep",
            starts_at=now,
            expires_at=None,
            emergency_stopped=False,
        )
        session.add(engagement)
        await session.flush()
    elif engagement.status != EngagementStatus.ACTIVE:
        # This record is the import sink, not a scan authorization record.  Keep
        # its canonical lifecycle active even if an operator previously changed it.
        engagement.status = EngagementStatus.ACTIVE
        engagement.expires_at = None
        await session.flush()
    return engagement


def _inventory_hosts(inventory: list[dict[str, Any]]) -> tuple[list[str], dict[str, str]]:
    hosts: list[str] = []
    seen_hosts: set[str] = set()
    package_hosts: dict[str, str] = {}
    for item in inventory:
        if not isinstance(item, dict):
            continue
        raw_host = item.get("host")
        raw_package = item.get("package")
        host = str(raw_host).strip() if raw_host is not None else ""
        package = str(raw_package).strip() if raw_package is not None else ""
        if host and host not in seen_hosts:
            hosts.append(host)
            seen_hosts.add(host)
        if host and package and package not in package_hosts:
            package_hosts[package] = host
    return hosts, package_hosts


async def receive_center_deep(
    session: AsyncSession,
    *,
    raw_body: bytes,
    webhook_id: str | None,
    webhook_timestamp: str | None,
    webhook_signature: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify and import one signed Center Deep delivery.

    The caller owns the final commit.  A failed import therefore rolls back the
    source delivery marker and all rows together with the request transaction.
    """

    if not webhook_id or not webhook_timestamp:
        raise _webhook_error(
            "missing webhook authentication headers",
            code="invalid_webhook_signature",
            status_code=401,
        )

    delivery_at = _delivery_now(now)
    _parse_timestamp(webhook_timestamp, now_epoch=delivery_at.timestamp())
    source = await _matching_source(
        session,
        webhook_id=webhook_id,
        timestamp=webhook_timestamp,
        signature_header=webhook_signature,
        raw_body=raw_body,
    )
    if source is None:
        raise _webhook_error(
            "invalid webhook signature",
            code="invalid_webhook_signature",
            status_code=401,
        )

    if _is_recent_duplicate(source, webhook_id, delivery_at):
        return {"duplicate": True}

    try:
        document = json.loads(raw_body)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValidationAppError(
            "webhook body must be valid JSON",
            code="invalid_webhook_body",
        ) from exc
    try:
        event = CenterDeepWebhook.model_validate(document)
    except ValidationError as exc:
        raise ValidationAppError(
            "webhook body does not match the Center Deep contract",
            code="invalid_webhook_body",
            detail=exc.errors(),
        ) from exc

    if event.type != "monitor.run.completed":
        raise ValidationAppError(
            "unsupported Center Deep webhook type",
            code="invalid_webhook_body",
        )

    # The source lookup tried each organization context until the HMAC proved the
    # tenant.  Every read/write below is now bound through the matched RLS context.
    await set_org_context(session, source.org_id)

    situation = event.data.situation or document.get("data", {}).get("situation") or {}
    if not isinstance(situation, dict):
        situation = {}
    inventory = situation.get("inventory") or []
    kev_matches = situation.get("kev_matches") or []
    comparisons = situation.get("comparisons") or []
    if not isinstance(inventory, list):
        inventory = []
    if not isinstance(kev_matches, list):
        kev_matches = []
    if not isinstance(comparisons, list):
        comparisons = []

    typed_situation = event.data.situation
    if typed_situation is None:
        # Preserve the permissive contract shape while keeping the import path
        # deterministic for a completed run without a situation section.
        inventory_items: list[dict[str, Any]] = [
            item for item in inventory if isinstance(item, dict)
        ]
        match_items: list[dict[str, Any]] = [
            item for item in kev_matches if isinstance(item, dict)
        ]
        comparison_items: list[dict[str, Any]] = [
            item for item in comparisons if isinstance(item, dict)
        ]
        observed_at = None
    else:
        inventory_items = [item for item in typed_situation.inventory if isinstance(item, dict)]
        match_items = [item for item in typed_situation.kev_matches if isinstance(item, dict)]
        comparison_items = [
            item for item in typed_situation.comparisons if isinstance(item, dict)
        ]
        observed_at = typed_situation.observed_at

    engagement = await _ensure_external_engagement(
        session, org_id=source.org_id, now=delivery_at
    )
    hosts, package_hosts = _inventory_hosts(inventory_items)

    run_stmt = select(Run).where(
        Run.org_id == source.org_id,
        Run.engagement_id == engagement.id,
        Run.engine == CENTER_DEEP_KIND,
        Run.strix_run_id == event.data.run_id,
    )
    run = (await session.execute(run_stmt)).scalars().first()
    if run is None:
        run = Run(
            engagement_id=engagement.id,
            org_id=source.org_id,
            strix_run_id=event.data.run_id,
            engine=CENTER_DEEP_KIND,
            mode=RunMode.STANDARD,
            model_profile=DEFAULT_MODEL_PROFILE,
            targets=hosts,
            status=RunStatus.COMPLETED,
            started_at=delivery_at,
            ended_at=delivery_at,
            report_path=event.data.report_url,
        )
        session.add(run)
        await session.flush()

    finding_repo = FindingRepository(session)
    findings_created = 0
    findings_seen = 0
    common_evidence = {
        "observed_at": observed_at,
        "run_id": event.data.run_id,
        "report_url": event.data.report_url,
        "source": CENTER_DEEP_KIND,
        # FindingRepository uses this field to maintain also_found_by.
        "engine": CENTER_DEEP_KIND,
    }

    for match in match_items:
        host = str(match.get("host") or "").strip()
        package = str(match.get("package") or "").strip()
        version = str(match.get("version") or "").strip()
        cve = str(match.get("cve") or "").strip()
        state = str(match.get("state") or "").upper()
        if match.get("kev") is True:
            severity = FindingSeverity.CRITICAL
        elif state == "ELEVATED":
            severity = FindingSeverity.HIGH
        elif state == "WATCH":
            severity = FindingSeverity.MEDIUM
        else:
            severity = FindingSeverity.LOW
        evidence = {**match, **common_evidence}
        await finding_repo.create(
            run_id=run.id,
            engagement_id=engagement.id,
            org_id=source.org_id,
            title=f"{package} {version}: {cve}",
            severity=severity,
            cwe=cve,
            endpoint=f"{host}/{package}",
            fingerprint=_fingerprint(source.org_id, host, package, cve),
            evidence=evidence,
            verified_by="center-deep-research",
            status=FindingStatus.NEW,
        )
        if finding_repo.last_create_deduped:
            findings_seen += 1
        else:
            findings_created += 1

    for comparison in comparison_items:
        if comparison.get("security_newer") is not True:
            continue
        package = str(comparison.get("package") or "").strip()
        current = str(comparison.get("current") or "").strip()
        latest_tag = str(comparison.get("latest_tag") or "").strip()
        host = str(comparison.get("host") or package_hosts.get(package) or "").strip()
        endpoint = f"{host}/{package}" if host else package
        evidence = {**comparison, **common_evidence}
        await finding_repo.create(
            run_id=run.id,
            engagement_id=engagement.id,
            org_id=source.org_id,
            title=f"{package} {current} is behind security release {latest_tag}",
            severity=FindingSeverity.LOW,
            endpoint=endpoint,
            fingerprint=_fingerprint(source.org_id, host, package, latest_tag),
            evidence=evidence,
            verified_by="center-deep-research",
            status=FindingStatus.NEW,
        )
        if finding_repo.last_create_deduped:
            findings_seen += 1
        else:
            findings_created += 1

    source.last_delivery_at = delivery_at
    source.last_webhook_id = webhook_id
    await session.flush()
    return {
        "findings_created": findings_created,
        "findings_seen": findings_seen,
        "run_id": run.id,
    }


__all__ = [
    "CENTER_DEEP_KIND",
    "EXTERNAL_ENGAGEMENT_NAME",
    "IngestRepository",
    "IngestSourceRepository",
    "receive_center_deep",
]
