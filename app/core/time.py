"""Application time conventions for API-boundary datetime values."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from pydantic import TypeAdapter, ValidationError

BUSINESS_TIMEZONE = "America/New_York"

_BUSINESS_ZONE = ZoneInfo(BUSINESS_TIMEZONE)
_DATETIME_ADAPTER = TypeAdapter(datetime)
_time_logger = logging.getLogger("secops.core.time")


def _parse_datetime(value: Any) -> Any:
    if value is None:
        return None
    try:
        return (
            value
            if isinstance(value, datetime)
            else _DATETIME_ADAPTER.validate_python(value)
        )
    except (TypeError, ValueError, ValidationError):
        return value


def normalize_datetime_to_utc(
    value: Any,
    *,
    on_naive: Callable[[datetime], None] | None = None,
) -> Any:
    """Return a datetime as an aware UTC instant.

    API clients historically send timezone-less datetimes. Those values are
    business wall-clock time, so attach the named business zone before converting
    to UTC. During the 2026-11-01 DST fall-back, the local 01:00–02:00 hour
    occurs twice; ``fold=0`` is selected explicitly, meaning the first
    occurrence (EDT). A naïve value is warned about and named in the warning.
    Invalid values are returned unchanged so Pydantic can report its normal
    field-specific validation error.

    ``on_naive`` receives the parsed naïve value and lets a request schema emit
    one warning for a request even when several datetime fields are timezone-less.
    """
    parsed = _parse_datetime(value)
    if not isinstance(parsed, datetime):
        return value

    if parsed.tzinfo is None:
        if on_naive is not None:
            on_naive(parsed)
        else:
            _time_logger.warning(
                "naive datetime %s interpreted as %s business time using fold=0 "
                "(first occurrence) and normalized to UTC",
                parsed.isoformat(),
                BUSINESS_TIMEZONE,
            )
        parsed = parsed.replace(tzinfo=_BUSINESS_ZONE, fold=0)
    return parsed.astimezone(UTC)


def normalize_stored_datetime_to_utc(value: Any) -> Any:
    """Return a persisted datetime as aware UTC, treating naïve data as UTC.

    Stored JSON and internal/database values are already UTC by convention. This
    is deliberately separate from :func:`normalize_datetime_to_utc`, whose
    naïve-input convention is only for client request bodies.
    """
    parsed = _parse_datetime(value)
    if not isinstance(parsed, datetime):
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


__all__ = [
    "BUSINESS_TIMEZONE",
    "normalize_datetime_to_utc",
    "normalize_stored_datetime_to_utc",
]
