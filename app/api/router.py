"""Aggregate API router — mounts every business router under ``/api/v1`` (spec §6).

:data:`api_router` is the single object the composition root includes::

    from app.api.router import api_router   # app.main, guarded import
    app.include_router(api_router)

It carries the ``/api/v1`` prefix and pulls in the resource routers, so the
full surface resolves as ``/api/v1/engagements…``, ``/api/v1/targets…``,
``/api/v1/runs…``, ``/api/v1/findings…``, the read-only console
``/api/v1/overview``, the agent-key management ``/api/v1/pats…``, and the console
``/api/v1/assistant/chat``. Each sub-router owns its own
``tags`` and every route enforces SSO + the ``security-ops`` entitlement +
tenant scope transitively through the dependencies in :mod:`app.api.deps`.

Imports are strict on purpose: this module fails to import if any sub-router is
broken, so ``app.main`` degrades to core-only (``/health``, ``/version``) rather
than mounting a partially-wired API. Ordering is irrelevant to correctness — the
sub-routers share no colliding paths (``/engagements/{id}/runs`` lives in the
runs router; ``/engagements/{id}/attack-path`` in the attack-path router;
``/engagements/{id}/activate|stop|scope/check|report`` in the engagements
router) — but they are listed in the spec's resource order.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.abuse import router as abuse_router
from app.api.assistant import router as assistant_router
from app.api.attack_path import router as attack_path_router
from app.api.campaigns import router as campaigns_router
from app.api.compliance import router as compliance_router
from app.api.engagements import router as engagements_router
from app.api.findings import router as findings_router
from app.api.me import router as me_router
from app.api.remediation import router as remediation_router
from app.api.scheduled_scans import router as scheduled_scans_router
from app.api.overview import router as overview_router
from app.api.pats import router as pats_router
from app.api.runs import router as runs_router
from app.api.targets import router as targets_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(engagements_router)
api_router.include_router(attack_path_router)
api_router.include_router(targets_router)
api_router.include_router(runs_router)
api_router.include_router(findings_router)
api_router.include_router(remediation_router)
api_router.include_router(campaigns_router)
api_router.include_router(overview_router)
api_router.include_router(compliance_router)
api_router.include_router(pats_router)
api_router.include_router(scheduled_scans_router)
api_router.include_router(abuse_router)
api_router.include_router(assistant_router)
api_router.include_router(me_router)

__all__ = ["api_router"]
