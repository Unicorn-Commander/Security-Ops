"""HTTP API layer for Security-Ops (FastAPI routers, spec §6).

Each sub-module in this package exposes a module-level ``router: APIRouter``
that ``app.api.router.api_router`` aggregates under the ``/api/v1`` prefix.
Kept import-side-effect free on purpose (no re-exports) so the composition
root controls include order and no import cycles form.
"""
