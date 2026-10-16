"""Application time conventions for API-boundary datetime values."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from pydantic import TypeAdapter, ValidationError

BUSINESS_TIMEZONE = "America/New_York"

_BUSINESS_ZONE = ZoneInfo(BUSINESS_TIMEZONE)
_DATETIME_ADAPTER = TypeAdapter(datetime)


def normalize_datetime_to_utc(
    value: Any,
    *,
    on_naive: Callable[[], None] | None = None,
) -> Any:
    """Return a datetime as an aware UTC instant.

    API clients historically send timezone-less datetimes. Those values are
    business wall-clock time, so attach the named business zone before converting
    to UTC. Invalid values are returned unchanged so Pydantic can report its
    normal field-specific validation error.

    ``on_naive`` lets a request schema emit one warning for a request even when
    several datetime fields are timezone-less.
    """
    if value is None:
        return None

    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else _DATETIME_ADAPTER.validate_python(value)
        )
    except (TypeError, ValueError, ValidationError):
        return value

    if parsed.tzinfo is None:
        if on_naive is not None:
            on_naive()
        parsed = parsed.replace(tzinfo=_BUSINESS_ZONE)
    return parsed.astimezone(timezone.utc)


__all__ = ["BUSINESS_TIMEZONE", "normalize_datetime_to_utc"]
