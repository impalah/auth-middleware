from __future__ import annotations

import asyncio
from enum import StrEnum

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Mount

from auth_middleware.authz import (
    Authz,
    AuthzContext,
    AuthzHooks,
    ConfigurationError,
    ErrorPolicy,
    NewAssignment,
    ScopeFromCallable,
    ScopeFromPath,
    ScopeKindMismatchError,
    ScopeRef,
    UnknownPermissionError,
    declared_permissions,
    has_permission,
    permission_extra,
    require_permission,
)
from auth_middleware.authz.stores import InMemoryAssignmentStore
from auth_middleware.settings import settings
from auth_middleware.types.user import User


class P(StrEnum):
    READ = "design.read"
    WRITE = "design.write"


def _user(uid: str, groups=()) -> User:
    return User(id=uid, name=uid, email=f"{uid}@example.com", groups=list(groups))


class FakeAuth(BaseHTTPMiddleware):
    """Puts the user named by X-User on request.state (stands in for the JWT middleware)."""

    async def dispatch(self, request, call_next):
        who = request.headers.get("x-user")
        if who == "synthetic":
            request.state.current_user = User.synthetic()
        elif who:
            groups = request.headers.get("x-groups", "")
            request.state.current_user = _user(who, [g for g in groups.split(",") if g])
        return await call_next(request)


@pytest.fixture
def store():
    st = InMemoryAssignmentStore()
    s = ScopeRef("studio", "s1")

    async def fill():
        await st.assign(NewAssignment("editor", s, "EDITOR"))
        await st.assign(NewAssignment("reader", s, "READER"))

    asyncio.run(fill())
    return st


def _app(catalog, store, **kw) -> FastAPI:
    app = FastAPI()
    app.add_middleware(FakeAuth)
    authz = Authz.build(
        catalog=catalog,
        store=store,
        group_roles={"admins": "PLATFORM_ADMIN"},
        **kw,
    )
    authz.install(app)

    @app.get(
        "/studios/{studio_id}/design",
        openapi_extra=permission_extra(P.READ),
    )
    async def read(
        studio_id: str,
        ctx: AuthzContext = Depends(
            require_permission(P.READ, scope=ScopeFromPath("studio", "studio_id"))
        ),
    ):
        return {"roles": sorted(ctx.roles)}

    @app.put("/studios/{studio_id}/design")
    async def write(
        studio_id: str,
        ctx: AuthzContext = Depends(
            require_permission(P.WRITE, scope=ScopeFromPath("studio", "studio_id"))
        ),
    ):
        return {"ok": True}

    @app.get("/platform")
    async def platform(ctx=Depends(require_permission("platform.admin"))):
        return {"ok": True}

    @app.get("/open")
    async def open_():
        return {}

    return app


def test_matrix(catalog, store):
    client = TestClient(_app(catalog, store))
    ok = client.get("/studios/s1/design", headers={"x-user": "reader"})
    assert ok.status_code == 200 and ok.json() == {"roles": ["READER"]}
    denied = client.put("/studios/s1/design", headers={"x-user": "reader"})
    assert denied.status_code == 403
    assert denied.json() == {
        "detail": {"error": "forbidden", "required_permission": "design.write"}
    }
    stranger = client.get("/studios/s1/design", headers={"x-user": "stranger"})
    unknown = client.get("/studios/nope/design", headers={"x-user": "reader"})
    assert stranger.status_code == unknown.status_code == 404
    assert stranger.json() == unknown.json()
    anon = client.get("/studios/s1/design")
    assert anon.status_code == 401
    assert anon.headers["www-authenticate"] == "Bearer"
    assert (
        client.get("/studios/s1/design", headers={"x-user": "synthetic"}).status_code
        == 401
    )


def test_group_platform_scope(catalog, store):
    client = TestClient(_app(catalog, store))
    assert (
        client.get(
            "/platform", headers={"x-user": "a", "x-groups": "admins"}
        ).status_code
        == 200
    )
    assert client.get("/platform", headers={"x-user": "b"}).status_code == 403


def test_custom_error_policy(catalog, store):
    class Teapot(Exception):
        pass

    app = _app(
        catalog,
        store,
        error_policy=ErrorPolicy(denied=lambda r, e: Teapot("no")),
    )
    client = TestClient(app, raise_server_exceptions=True)
    with pytest.raises(Teapot):
        client.put("/studios/s1/design", headers={"x-user": "reader"})


def test_guard_still_enforces_when_disabled(catalog, store, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MIDDLEWARE_DISABLED", True)
    app = FastAPI()
    app.add_middleware(FakeAuth)
    Authz.build(catalog=catalog, store=store).install(
        app, allow_disabled_for_development=True
    )

    @app.get("/p")
    async def p(ctx=Depends(require_permission("platform.admin"))):
        return {}

    assert TestClient(app).get("/p", headers={"x-user": "synthetic"}).status_code == 401


def test_validate_routes_catches_mistakes(catalog, store):
    authz = Authz.build(catalog=catalog, store=store)

    app = FastAPI()

    @app.get("/x", dependencies=[Depends(require_permission("typo.perm"))])
    async def x(): ...

    with pytest.raises(UnknownPermissionError):
        authz.validate_routes(app)

    app = FastAPI()

    @app.get("/y", dependencies=[Depends(require_permission("design.read"))])
    async def y(): ...

    with pytest.raises(ScopeKindMismatchError):
        authz.validate_routes(app)

    app = FastAPI()

    @app.get(
        "/z",
        dependencies=[
            Depends(
                require_permission("design.read", scope=ScopeFromPath("studio", "id"))
            )
        ],
    )
    async def z(): ...

    with pytest.raises(ConfigurationError):
        authz.validate_routes(app)


def test_startup_fails_on_unknown_permission(catalog, store):
    app = FastAPI()
    Authz.build(catalog=catalog, store=store).install(app)

    @app.get("/x", dependencies=[Depends(require_permission("typo.perm"))])
    async def x(): ...

    with pytest.raises(UnknownPermissionError):
        with TestClient(app):
            pass


def test_declared_permissions_lists_every_operation(catalog, store):
    declared = declared_permissions(_app(catalog, store))
    assert declared[("GET", "/studios/{studio_id}/design")] == "design.read"
    assert declared[("PUT", "/studios/{studio_id}/design")] is None
    assert declared[("GET", "/open")] is None


def test_mounted_subapp_with_explicit_authz(catalog, store):
    authz = Authz.build(catalog=catalog, store=store)
    sub = FastAPI()  # no app.state.authz here
    sub.add_middleware(FakeAuth)

    @sub.get("/studios/{sid}/design")
    async def read(
        sid: str,
        ctx=Depends(
            require_permission(
                "design.read", scope=ScopeFromPath("studio", "sid"), authz=authz
            )
        ),
    ):
        return {"ok": True}

    root = Starlette(routes=[Mount("/api", app=sub)])
    assert (
        TestClient(root)
        .get("/api/studios/s1/design", headers={"x-user": "reader"})
        .status_code
        == 200
    )


def test_has_permission_and_hooks_and_callable_scope(catalog, store):
    events = []
    app = FastAPI()
    app.add_middleware(FakeAuth)
    Authz.build(
        catalog=catalog, store=store, hooks=AuthzHooks(on_decision=events.append)
    ).install(app)

    @app.get("/h")
    async def h(
        request: __import__("starlette.requests").requests.Request,
        ctx=Depends(
            require_permission(
                "design.read", scope=ScopeFromCallable("studio", lambda r: "s1")
            )
        ),
    ):
        can = await has_permission(request, "design.write", ScopeRef("studio", "s1"))
        return {"can_write": can, "ctx": request.state.authz_context.principal.id}

    client = TestClient(app)
    assert client.get("/h", headers={"x-user": "reader"}).json() == {
        "can_write": False,
        "ctx": "reader",
    }
    assert client.get("/h", headers={"x-user": "editor"}).json()["can_write"] is True
    assert [e.kind.value for e in events] == ["allowed", "allowed"]
