"""External finding ingest and operator source-management routes.

The Center Deep receiver is intentionally declared without ``CurrentOrg`` or
``EntitledUser``: its Standard Webhooks signature is the authentication
boundary, and the signed source identifies the organization.  The four source
administration routes below are ordinary SSO + entitlement routes.  Imported
deliveries do not call ``runs_start`` or the attestation/scan gates because they
represent completed external watch observations, not scans initiated by
Security-Ops.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Header, Request, status

from app.api.deps import CurrentOrg, DbSession, EntitledUser
from app.core.errors import NotFoundError
from app.repositories.ingest import (
    IngestSourceRepository,
    receive_center_deep,
)
from app.schemas.common import Page
from app.schemas.ingest import (
    IngestDeliveryResponse,
    IngestDuplicateResponse,
    IngestSourceCreate,
    IngestSourceCreated,
    IngestSourceRead,
)

router = APIRouter(tags=["ingest"])


def _created_response(source, secret: str) -> IngestSourceCreated:
    read = IngestSourceRead.model_validate(source)
    return IngestSourceCreated(**read.model_dump(), secret=secret)


async def _load_source(session, source_id: uuid.UUID, org):
    source = await IngestSourceRepository(session).get_for_org(source_id, org.id)
    if source is None:
        raise NotFoundError("Ingest source not found")
    return source


@router.post(
    "/ingest-sources",
    response_model=IngestSourceCreated,
    status_code=status.HTTP_201_CREATED,
)
async def create_ingest_source_route(
    data: IngestSourceCreate,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> IngestSourceCreated:
    """Mint a source and return its webhook secret exactly once."""

    source, secret = await IngestSourceRepository(session).create(
        org_id=org.id,
        name=data.name,
        kind=data.kind,
        created_by=user.id,
    )
    await session.commit()
    return _created_response(source, secret)


@router.get("/ingest-sources", response_model=Page[IngestSourceRead])
async def list_ingest_sources_route(
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> Page[IngestSourceRead]:
    """List source metadata only; no stored secret is serialized."""

    items = await IngestSourceRepository(session).list_for_org(org.id)
    return Page[IngestSourceRead](
        items=[IngestSourceRead.model_validate(item) for item in items],
        total=len(items),
        limit=len(items),
        offset=0,
    )


@router.post(
    "/ingest-sources/{source_id}/rotate",
    response_model=IngestSourceCreated,
)
async def rotate_ingest_source_route(
    source_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> IngestSourceCreated:
    """Rotate a source secret and return the replacement exactly once."""

    source = await _load_source(session, source_id, org)
    secret = await IngestSourceRepository(session).rotate(source)
    await session.commit()
    return _created_response(source, secret)


@router.delete(
    "/ingest-sources/{source_id}",
    response_model=IngestSourceRead,
)
async def disable_ingest_source_route(
    source_id: uuid.UUID,
    session: DbSession,
    org: CurrentOrg,
    user: EntitledUser,
) -> IngestSourceRead:
    """Disable a source without deleting its delivery history."""

    source = await _load_source(session, source_id, org)
    await IngestSourceRepository(session).disable(source)
    await session.commit()
    return IngestSourceRead.model_validate(source)


@router.post("/ingest/center-deep")
async def center_deep_ingest_route(
    request: Request,
    session: DbSession,
    webhook_id: Annotated[str | None, Header(alias="webhook-id")] = None,
    webhook_timestamp: Annotated[
        str | None, Header(alias="webhook-timestamp")
    ] = None,
    webhook_signature: Annotated[
        str | None, Header(alias="webhook-signature")
    ] = None,
) -> IngestDeliveryResponse | IngestDuplicateResponse:
    """Receive a signed Center Deep delivery without SSO.

    The raw request bytes are passed to HMAC verification before JSON parsing.
    A duplicate webhook id is a committed no-op; a successful non-duplicate
    delivery owns the transaction commit after the engagement, run, findings,
    and source delivery marker have all flushed.
    """

    result = await receive_center_deep(
        session,
        raw_body=await request.body(),
        webhook_id=webhook_id,
        webhook_timestamp=webhook_timestamp,
        webhook_signature=webhook_signature,
    )
    if result.get("duplicate"):
        return IngestDuplicateResponse.model_validate(result)
    await session.commit()
    return IngestDeliveryResponse.model_validate(result)


__all__ = ["router"]
