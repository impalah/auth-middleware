from __future__ import annotations

import pathlib

import pytest
from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.requests import Request

from auth_middleware.authz import (
    Authz,
    ConfigurationError,
    ErrorPolicy,
    PermissionDeniedError,
    ScopeNotVisibleError,
)
from auth_middleware.authz.stores import InMemoryAssignmentStore
from auth_middleware.settings import settings


def _request(app=None) -> Request:
    return Request({"type": "http", "app": app or Starlette(), "headers": []})


def test_build_validates_combinations(catalog):
    store = InMemoryAssignmentStore()
    with pytest.raises(ConfigurationError):
        Authz.build(catalog=catalog)
    with pytest.raises(ConfigurationError):
        Authz.build(catalog=catalog, store=store, store_factory=lambda r: store)
    with pytest.raises(ConfigurationError):
        Authz.build(catalog=catalog, group_roles={"g": "NOPE"})
    Authz.build(catalog=catalog, group_roles={"g": "PLATFORM_ADMIN"})


@pytest.mark.asyncio
async def test_factory_called_once_per_authorizer(catalog):
    calls = []

    async def factory(request):
        calls.append(request)
        return InMemoryAssignmentStore()

    authz = Authz.build(catalog=catalog, store_factory=factory)
    await authz.authorizer_for(_request())
    await authz.authorizer_for(_request())
    assert len(calls) == 2


def test_install_refuses_disabled(catalog, monkeypatch):
    authz = Authz.build(catalog=catalog, store=InMemoryAssignmentStore())
    monkeypatch.setattr(settings, "AUTH_MIDDLEWARE_DISABLED", True)
    with pytest.raises(ConfigurationError):
        authz.install(FastAPI())
    app = FastAPI()
    authz.install(app, allow_disabled_for_development=True)
    assert app.state.authz is authz


def test_of_requires_install(catalog):
    with pytest.raises(ConfigurationError):
        Authz.of(_request())
    authz = Authz.build(catalog=catalog, store=InMemoryAssignmentStore())
    for app in (FastAPI(), Starlette()):
        authz.install(app)
        assert Authz.of(_request(app)) is authz


@pytest.mark.asyncio
async def test_aclose_idempotent_and_closes_store(catalog):
    class Closable(InMemoryAssignmentStore):
        closed = 0

        async def aclose(self):
            Closable.closed += 1

    authz = Authz.build(catalog=catalog, store=Closable())
    await authz.aclose()
    await authz.aclose()
    assert Closable.closed == 1


def test_default_error_policy():
    from auth_middleware.authz import ScopeRef

    policy = ErrorPolicy()
    scope = ScopeRef("studio", "a")
    req = _request()
    assert policy.not_visible(req, ScopeNotVisibleError(scope)).status_code == 404
    denied = policy.denied(req, PermissionDeniedError("x.y", scope))
    assert denied.status_code == 403
    assert denied.detail == {"error": "forbidden", "required_permission": "x.y"}
    unauth = policy.unauthenticated(req)
    assert unauth.status_code == 401
    assert unauth.headers["WWW-Authenticate"] == "Bearer"


def test_no_environment_reads_or_singletons():
    root = pathlib.Path(__file__).parents[2] / "src/auth_middleware/authz"
    for path in root.rglob("*.py"):
        text = path.read_text()
        assert "os.environ" not in text and "getenv" not in text, path
        assert "\nauthz = Authz" not in text, path
