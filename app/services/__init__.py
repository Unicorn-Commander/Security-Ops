"""app.services — the business-logic / use-case layer.

Sits between the thin API routers (``app.api``) and the data/authz/engine layers.
Services own their transactions (they commit), emit the append-only audit rows,
and orchestrate the domain rules the routers must not:

* :mod:`app.services.runs` — run lifecycle. ``start_run`` is the SOLE caller of
  the target-authorization gate (``app.authz.gate.enforce_scope``): no run is
  created and nothing is launched until every one of its targets clears the gate
  (spec §4). This is the product's central trust boundary.
* :mod:`app.services.engagements` — create + DRAFT->ACTIVE / emergency-stop, with
  activation failing closed unless every in-scope target is validly attested.
* :mod:`app.services.targets` — register (UNATTESTED) + list authorized targets.

Callers import the concrete function directly (e.g.
``from app.services.runs import start_run``); the public surface is also
re-exported here for convenience.

Dependency direction (no cycles): services -> {authz, engine, audit, repositories,
schemas, models, core, auth (typing only)}. Nothing in those layers imports
services.
"""

from __future__ import annotations

from app.services.engagements import (
    activate_engagement,
    create_engagement,
    emergency_stop,
)
from app.services.runs import get_run, start_run, stop_run
from app.services.targets import list_targets, register_target

__all__ = [
    # engagements
    "create_engagement",
    "activate_engagement",
    "emergency_stop",
    # runs
    "get_run",
    "start_run",
    "stop_run",
    # targets
    "list_targets",
    "register_target",
]
