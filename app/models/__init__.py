"""Security-Ops ORM models.

Importing this package imports every model AND re-exports every enum, so that
``Base.metadata`` is fully populated on ``import app.models`` (used by
``app.db.session.init_db`` and ``migrations/env.py``).
"""

from __future__ import annotations

from app.models.audit import AuditAction, AuditEvent
from app.models.engagement import Engagement, EngagementStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.organization import Organization
from app.models.pat import PersonalAccessToken
from app.models.run import Run, RunMode, RunStatus
from app.models.run_queue import RunQueueEntry
from app.models.target import (
    AttestationMethod,
    AttestationStatus,
    AuthorizedTarget,
    TargetKind,
)

__all__ = [
    # organization
    "Organization",
    # personal access token (agent credentials)
    "PersonalAccessToken",
    # target
    "AuthorizedTarget",
    "TargetKind",
    "AttestationMethod",
    "AttestationStatus",
    # engagement
    "Engagement",
    "EngagementStatus",
    # run
    "Run",
    "RunStatus",
    "RunMode",
    "RunQueueEntry",
    # finding
    "Finding",
    "FindingSeverity",
    "FindingStatus",
    # audit
    "AuditEvent",
    "AuditAction",
]
