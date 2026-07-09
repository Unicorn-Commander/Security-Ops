"""RunEvent schema — serializes a live-trace row for the SSE stream / replay.

``RunEventRead.model_validate(row)`` renders one ``run_events`` row as the JSON
``data:`` payload of a Server-Sent Event; ``seq`` doubles as the SSE ``id:`` so a
reconnecting client resumes past the last event it saw.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class RunEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    run_id: uuid.UUID
    seq: int
    event_type: str
    message: str | None = None
    data: dict[str, Any] | None = None
    created_at: datetime
