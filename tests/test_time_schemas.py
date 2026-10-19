"""API-boundary time normalization for authorization inputs."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.authz.gate import _load_scope
from app.core.time import normalize_datetime_to_utc
from app.models.target import AttestationMethod
from app.schemas.engagement import EngagementCreate, RulesOfEngagement
from app.schemas.target import AttestationRequest


def test_naive_attestation_expiry_is_business_time_not_utc():
    request = AttestationRequest(
        method=AttestationMethod.OWNED,
        expires_at=datetime(2026, 10, 16, 23, 30),
    )

    assert request.expires_at == datetime(2026, 10, 17, 3, 30, tzinfo=UTC)


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

    assert window.time_window_start == datetime(2026, 11, 1, 4, 30, tzinfo=UTC)
    assert window.time_window_end == datetime(2026, 11, 1, 7, 30, tzinfo=UTC)
    assert window.time_window_end - window.time_window_start == timedelta(hours=3)


def test_stored_roe_window_is_utc_when_gate_reloads_json():
    engagement = SimpleNamespace(
        scope={"in_scope": [{"kind": "DOMAIN", "value": "example.com"}]},
        rules_of_engagement={"time_window_start": "2026-10-16T23:30:00"},
    )

    scope = _load_scope(engagement)

    assert scope.rules_of_engagement.time_window_start == datetime(
        2026, 10, 16, 23, 30, tzinfo=UTC
    )


def test_naive_engagement_request_window_is_business_time():
    request = EngagementCreate.model_validate(
        {
            "name": "local window",
            "scope": {
                "in_scope": [{"kind": "DOMAIN", "value": "example.com"}],
                "rules_of_engagement": {
                    "time_window_start": "2026-10-16T23:30:00",
                },
            },
        }
    )

    assert request.scope.rules_of_engagement.time_window_start == datetime(
        2026, 10, 17, 3, 30, tzinfo=UTC
    )


def test_aware_roe_window_preserves_the_same_instant_for_request_and_storage():
    aware = "2026-10-16T23:30:00-04:00"
    stored = RulesOfEngagement.model_validate({"time_window_start": aware})
    request = EngagementCreate.model_validate(
        {
            "name": "aware window",
            "scope": {
                "in_scope": [{"kind": "DOMAIN", "value": "example.com"}],
                "rules_of_engagement": {"time_window_start": aware},
            },
        }
    )
    expected = datetime(2026, 10, 17, 3, 30, tzinfo=UTC)

    assert stored.time_window_start == expected
    assert request.scope.rules_of_engagement.time_window_start == expected


def test_naive_fold_time_uses_first_edt_occurrence_and_logs_value(caplog):
    value = "2026-11-01T01:30:00"
    caplog.set_level(logging.WARNING, logger="secops.core.time")

    normalized = normalize_datetime_to_utc(value)

    assert normalized == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)
    warnings = [
        record for record in caplog.records if record.name == "secops.core.time"
    ]
    assert any(
        value in record.getMessage() and "fold=0" in record.getMessage()
        for record in warnings
    )


def test_naive_spring_forward_gap_is_rejected_as_request_validation():
    with pytest.raises(ValidationError) as excinfo:
        AttestationRequest(
            method=AttestationMethod.OWNED,
            expires_at="2026-03-08T02:30:00",
        )

    message = str(excinfo.value)
    assert "spring-forward DST gap" in message
    assert "America/New_York" in message
    assert "local time does not exist" in message


def test_naive_spring_forward_boundary_times_are_accepted():
    assert normalize_datetime_to_utc("2026-03-08T01:59:00") == datetime(
        2026, 3, 8, 6, 59, tzinfo=UTC
    )
    assert normalize_datetime_to_utc("2026-03-08T03:00:00") == datetime(
        2026, 3, 8, 7, 0, tzinfo=UTC
    )


def test_aware_datetime_in_spring_forward_wall_gap_keeps_its_offset():
    aware = datetime(2026, 3, 8, 2, 30, tzinfo=timezone(timedelta(hours=-5)))

    request = AttestationRequest(method=AttestationMethod.OWNED, expires_at=aware)

    assert request.expires_at == aware.astimezone(UTC)


def test_aware_attestation_expiry_keeps_the_same_instant():
    aware = datetime(2026, 10, 16, 23, 30, tzinfo=timezone(timedelta(hours=-4)))
    request = AttestationRequest(method=AttestationMethod.OWNED, expires_at=aware)

    assert request.expires_at == aware.astimezone(UTC)


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
    assert "2026-10-16T09:00:00" in warnings[0].getMessage()
