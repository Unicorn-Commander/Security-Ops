"""Center Deep webhook ingest: signing, idempotence, and tenant isolation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.api.ingest import (
    create_ingest_source_route,
    disable_ingest_source_route,
)
from app.auth.sso import AuthUser, UserRole
from app.core.errors import AppError
from app.models.engagement import Engagement
from app.models.finding import Finding, FindingSeverity
from app.models.ingest_source import IngestSource
from app.models.organization import Organization
from app.models.run import Run
from app.repositories.ingest import IngestSourceRepository, receive_center_deep
from app.schemas.ingest import IngestSourceCreate, IngestSourceRead
from tests.conftest import make_org


NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


def _operator(org_slug: str) -> AuthUser:
    return AuthUser(
        id=f"operator-{org_slug}",
        email=f"operator-{org_slug}@example.com",
        role=UserRole.OPERATOR,
        org_slug=org_slug,
        apps=["security-ops"],
    )


def _body(*, webhook_id: str, run_id: str = "cdr-run-001") -> bytes:
    return json.dumps(
        {
            "type": "monitor.run.completed",
            "id": webhook_id,
            "timestamp": "2026-11-08T17:00:00Z",
            "data": {
                "monitor_id": "monitor-example-001",
                "run_id": run_id,
                "question": "Which example packages need a security update?",
                "status": "completed",
                "kind": "always",
                "reason": "scheduled",
                "drift": False,
                "report_url": f"https://research.example/runs/{run_id}",
                "situation": {
                    "feed": "kev",
                    "state": "ELEVATED",
                    "observed_at": "2026-11-08T16:59:00Z",
                    "complete": True,
                    "inventory": [
                        {
                            "host": "stack-host.example.com",
                            "package": "example-org/example-server",
                            "ecosystem": "Go",
                            "version": "1.0.0",
                            "repo": "example-org/example-server",
                        },
                        {
                            "host": "stack-host.example.com",
                            "package": "example-org/example-client",
                            "ecosystem": "npm",
                            "version": "2.0.0",
                            "repo": "example-org/example-client",
                        },
                        {
                            "host": "stack-host.example.com",
                            "package": "example-org/example-agent",
                            "ecosystem": "PyPI",
                            "version": "3.0.0",
                            "repo": "example-org/example-agent",
                        },
                    ],
                    "kev_matches": [
                        {
                            "host": "stack-host.example.com",
                            "package": "example-org/example-server",
                            "ecosystem": "Go",
                            "version": "1.0.0",
                            "cve": "CVE-2099-0001",
                            "osv_id": "GHSA-example-0001",
                            "kev": True,
                            "summary": "fictional critical advisory",
                            "published": None,
                            "state": "WATCH",
                        },
                        {
                            "host": "stack-host.example.com",
                            "package": "example-org/example-client",
                            "ecosystem": "npm",
                            "version": "2.0.0",
                            "cve": "CVE-2099-0002",
                            "osv_id": "GHSA-example-0002",
                            "kev": False,
                            "summary": "fictional elevated advisory",
                            "published": None,
                            "state": "ELEVATED",
                        },
                        {
                            "host": "stack-host.example.com",
                            "package": "example-org/example-agent",
                            "ecosystem": "PyPI",
                            "version": "3.0.0",
                            "cve": "CVE-2099-0003",
                            "osv_id": "GHSA-example-0003",
                            "kev": False,
                            "summary": "fictional watch advisory",
                            "published": None,
                            "state": "WATCH",
                        },
                    ],
                    "releases": [],
                    "comparisons": [
                        {
                            "package": "example-org/example-server",
                            "repo": "example-org/example-server",
                            "current": "1.0.0",
                            "latest_tag": "v1.1.0",
                            "comparison": "security release available",
                            "behind": True,
                            "security_newer": True,
                        }
                    ],
                },
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _signature(secret: str, webhook_id: str, timestamp: int, body: bytes) -> str:
    key = base64.b64decode(secret.removeprefix("whsec_"))
    signed = f"{webhook_id}.{timestamp}.".encode() + body
    digest = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return f"v1,{digest}"


async def _mint(session, org):
    result = await create_ingest_source_route(
        IngestSourceCreate(name="Center Deep example watch"),
        session,
        org,
        _operator(org.slug),
    )
    assert result.secret.startswith("whsec_")
    return result


async def _deliver(session, secret: str, *, webhook_id: str, body: bytes, now=NOW):
    result = await receive_center_deep(
        session,
        raw_body=body,
        webhook_id=webhook_id,
        webhook_timestamp=str(int(now.timestamp())),
        webhook_signature=_signature(secret, webhook_id, int(now.timestamp()), body),
        now=now,
    )
    if not result.get("duplicate"):
        await session.commit()
    return result


async def test_center_deep_import_and_idempotence(db_session):
    org = await make_org(db_session, slug="example-a")
    source = await _mint(db_session, org)
    first_id = "00000000-0000-4000-8000-000000000001"
    first_body = _body(webhook_id=first_id)

    first = await _deliver(db_session, source.secret, webhook_id=first_id, body=first_body)
    assert first["findings_created"] == 4
    assert first["findings_seen"] == 0

    engagements = list((await db_session.execute(select(Engagement))).scalars())
    runs = list((await db_session.execute(select(Run))).scalars())
    findings = list((await db_session.execute(select(Finding))).scalars())
    assert len(engagements) == 1
    assert engagements[0].name == "External watch: Center Deep Research"
    assert engagements[0].status.value == "ACTIVE"
    assert engagements[0].scope == {"external": True, "source": "center-deep"}
    assert engagements[0].rules_of_engagement == {"imported": True}
    assert engagements[0].expires_at is None
    assert len(runs) == 1
    assert runs[0].engine == "center-deep"
    assert runs[0].targets == ["stack-host.example.com"]
    assert runs[0].status.value == "COMPLETED"
    assert runs[0].report_path == "https://research.example/runs/cdr-run-001"
    assert len(findings) == 4
    assert sorted(f.severity.value for f in findings) == [
        "CRITICAL",
        "HIGH",
        "LOW",
        "MEDIUM",
    ]
    assert all(f.status.value == "NEW" for f in findings)
    assert all(f.verified_by == "center-deep-research" for f in findings)
    assert all(f.evidence["source"] == "center-deep" for f in findings)

    duplicate = await _deliver(
        db_session, source.secret, webhook_id=first_id, body=first_body
    )
    assert duplicate == {"duplicate": True}
    assert await db_session.scalar(select(func.count()).select_from(Run)) == 1
    assert await db_session.scalar(select(func.count()).select_from(Finding)) == 4

    changed_id = "00000000-0000-4000-8000-000000000002"
    # A retry/re-delivery can receive a new transport id while carrying the
    # same signed monitor result body; ``data.run_id`` is the second idempotency
    # key, so the existing run/findings must be reused.
    changed_body = first_body
    replay = await _deliver(
        db_session, source.secret, webhook_id=changed_id, body=changed_body
    )
    assert replay["findings_created"] == 0
    assert replay["findings_seen"] == 4
    assert await db_session.scalar(select(func.count()).select_from(Engagement)) == 1
    assert await db_session.scalar(select(func.count()).select_from(Run)) == 1
    assert await db_session.scalar(select(func.count()).select_from(Finding)) == 4


async def test_center_deep_rejects_bad_stale_and_disabled(db_session):
    org = await make_org(db_session, slug="example-a")
    org_id = org.id
    source = await _mint(db_session, org)
    webhook_id = "00000000-0000-4000-8000-000000000003"
    body = _body(webhook_id=webhook_id)
    timestamp = int(NOW.timestamp())

    with pytest.raises(AppError) as bad:
        await receive_center_deep(
            db_session,
            raw_body=body,
            webhook_id=webhook_id,
            webhook_timestamp=str(timestamp),
            webhook_signature="v1,not-the-signature",
            now=NOW,
        )
    assert bad.value.status_code == 401
    await db_session.rollback()

    stale_time = NOW - timedelta(seconds=301)
    stale_sig = _signature(source.secret, webhook_id, int(stale_time.timestamp()), body)
    with pytest.raises(AppError) as stale:
        await receive_center_deep(
            db_session,
            raw_body=body,
            webhook_id=webhook_id,
            webhook_timestamp=str(int(stale_time.timestamp())),
            webhook_signature=stale_sig,
            now=NOW,
        )
    assert stale.value.status_code == 409
    await db_session.rollback()

    source_id = await db_session.scalar(
        select(IngestSource.id).where(IngestSource.org_id == org_id)
    )
    org = await db_session.get(Organization, org_id)
    await disable_ingest_source_route(
        source_id, db_session, org, _operator("example-a")
    )
    with pytest.raises(AppError) as disabled:
        await receive_center_deep(
            db_session,
            raw_body=body,
            webhook_id=webhook_id,
            webhook_timestamp=str(timestamp),
            webhook_signature=_signature(source.secret, webhook_id, timestamp, body),
            now=NOW,
        )
    assert disabled.value.status_code == 401


async def test_center_deep_source_matching_keeps_orgs_isolated(db_session):
    org_a = await make_org(db_session, slug="example-a")
    org_b = await make_org(db_session, slug="example-b")
    source_a = await _mint(db_session, org_a)
    source_b, secret_b = await IngestSourceRepository(db_session).create(
        org_id=org_b.id,
        name="Center Deep example watch B",
        created_by="operator-example-b",
    )
    await db_session.commit()

    webhook_id = "00000000-0000-4000-8000-000000000004"
    body = _body(webhook_id=webhook_id, run_id="cdr-run-org-b")
    result = await _deliver(db_session, secret_b, webhook_id=webhook_id, body=body)
    assert result["findings_created"] == 4
    assert await db_session.scalar(
        select(func.count()).select_from(Finding).where(Finding.org_id == org_a.id)
    ) == 0
    assert await db_session.scalar(
        select(func.count()).select_from(Finding).where(Finding.org_id == org_b.id)
    ) == 4
    refreshed_a = await db_session.get(IngestSource, source_a.id)
    refreshed_b = await db_session.get(IngestSource, source_b.id)
    assert refreshed_a.last_delivery_at is None
    assert refreshed_b.last_webhook_id == webhook_id


async def test_ingest_source_listing_omits_secret(db_session):
    org = await make_org(db_session, slug="example-a")
    source = await _mint(db_session, org)
    rows = await IngestSourceRepository(db_session).list_for_org(org.id)
    assert len(rows) == 1
    assert rows[0].id == source.id
    read = IngestSourceRead.model_validate(rows[0])
    assert "secret" not in read.model_dump()
