"""Finding fingerprint deduplication."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select

from app.models.finding import Finding
from app.models.finding import FindingSeverity
from app.repositories.findings import FindingRepository
from tests.conftest import make_engagement, make_org


async def test_create_deduplicates_by_fingerprint(db_session):
    org = await make_org(db_session)
    engagement = await make_engagement(db_session, org)
    repo = FindingRepository(db_session)

    first = await repo.create(
        run_id=uuid.uuid4(),
        engagement_id=engagement.id,
        org_id=org.id,
        title="SQL injection in /login",
        severity=FindingSeverity.HIGH,
        cwe="CWE-89",
        endpoint="https://example.com/login",
        evidence={"engine": "nuclei", "confidence": "high"},
    )
    second = await repo.create(
        run_id=uuid.uuid4(),
        engagement_id=engagement.id,
        org_id=org.id,
        title="SQL injection in /login",
        severity=FindingSeverity.HIGH,
        cwe="CWE-89",
        endpoint="https://example.com/login",
        evidence={"engine": "opengrep", "confidence": "medium"},
    )

    assert second.id == first.id
    assert repo.last_create_deduped is True
    assert repo.dedup_count == 1
    assert second.evidence["also_found_by"] == ["opengrep"]

    total = await db_session.scalar(select(func.count()).select_from(Finding))
    assert int(total or 0) == 1
