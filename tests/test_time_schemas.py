"""API-boundary time normalization for authorization inputs."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.models.target import AttestationMethod
from app.schemas.engagement import EngagementCreate
from app.schemas.target import AttestationRequest


def test_naive_attestation_expiry_is_business_time_not_utc():
    request = AttestationRequest(
        method=AttestationMethod.OWNED,
        expires_at=datetime(2026, 10, 16, 23, 30),
    )

    assert request.expires_at == datetime(2026, 10, 17, 3, 30, tzinfo=timezone.utc)


def test_naive_engagement_window_crosses_fall_back_in_business_time():
    request = EngagementCreate.model_validate(
        {
            "name": "fall-back window",
            "scope": {
                "in_scope": [{"kind": "DOMAIN", "value": "example.com"}],
                "rules_of_engagement": {
                    "time_window_start": "2026-11-01T00:30:00",
                    "time_window_end": "2026-11-01T02:30:00",
                },
            },
            "expires_at": "2026-11-02T00:00:00",
        }
    )
    window = request.scope.rules_of_engagement

    assert window.time_window_start == datetime(2026, 11, 1, 4, 30, tzinfo=timezone.utc)
    assert window.time_window_end == datetime(2026, 11, 1, 7, 30, tzinfo=timezone.utc)
    assert window.time_window_end - window.time_window_start == timedelta(hours=3)


def test_aware_attestation_expiry_keeps_the_same_instant():
    aware = datetime(2026, 10, 16, 23, 30, tzinfo=timezone(timedelta(hours=-4)))
    request = AttestationRequest(method=AttestationMethod.OWNED, expires_at=aware)

    assert request.expires_at == aware.astimezone(timezone.utc)


def test_request_with_multiple_naive_datetimes_logs_once(caplog):
    caplog.set_level(logging.WARNING, logger="secops.schemas.time")

    EngagementCreate.model_validate(
        {
            "name": "one warning",
            "scope": {
                "in_scope": [{"kind": "DOMAIN", "value": "example.com"}],
                "rules_of_engagement": {
                    "time_window_start": "2026-11-01T00:30:00",
                    "time_window_end": "2026-11-01T02:30:00",
                },
            },
            "starts_at": "2026-10-16T09:00:00",
            "expires_at": "2026-11-02T00:00:00",
        }
    )

    warnings = [
        record for record in caplog.records if record.name == "secops.schemas.time"
    ]
    assert len(warnings) == 1
