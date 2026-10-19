"""Business routes must reach both the aggregate router and the actual app."""

from importlib import import_module

import pytest
from fastapi.routing import APIRoute


@pytest.mark.parametrize(
    "module_name",
    [
        "assistant",
        "attack_path",
        "campaigns",
        "compliance",
        "engagements",
        "findings",
        "me",
        "overview",
        "pats",
        "runs",
        "targets",
    ],
)
def test_business_router_mounts(module_name):
    from app.api.router import api_router
    from app.main import app

    router = import_module(f"app.api.{module_name}").router
    expected = {
        (f"/api/v1{route.path}", frozenset(route.methods), route.endpoint)
        for route in router.routes
    }
    assert expected, f"{module_name} has no routes"
    for mounted in (api_router, app):
        actual = {
            (route.path, frozenset(route.methods), route.endpoint)
            for route in mounted.routes
            if isinstance(route, APIRoute)
        }
        assert expected <= actual, f"{module_name} is not fully mounted"
