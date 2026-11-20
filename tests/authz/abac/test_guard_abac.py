"""AUTHZ-028: Authz runtime config and the guard's resource=."""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from auth_middleware.authz import (
    Authz,
    AuthzHooks,
    ConfigurationError,
    NewAssignment,
    ScopeFromPath,
    ScopeRef,
    declared_permissions,
    has_permission,
    permission_extra,
    require_permission,
)
from auth_middleware.authz.abac.cache import CachingPolicySource
from auth_middleware.authz.abac.config import AbacConfig
from auth_middleware.authz.abac.resources import ResourceFromPath
from auth_middleware.authz.abac.sources import StaticPolicySource
from auth_middleware.authz.abac.types import Effect, NewPolicy, Policy, PolicyScope
from auth_middleware.authz.stores import InMemoryAssignmentStore
from auth_middleware.types.user import User

STATUS = {"attr": "subject.assignment.tenant_status"}
OWNER = {"eq": [{"attr": "resource.attrs.owner_id"}, {"attr": "subject.id"}]}

SUSPENDED = NewPolicy(
    "studio-suspended-readonly",
    Effect.DENY,
    ("*.write", "*.delete"),
    PolicyScope("studio"),
    {"eq": [STATUS, "suspended"]},
)
OWNER_ONLY = NewPolicy(
    "owner-only-delete",
    Effect.REQUIRE,
    ("design.delete",),
    PolicyScope("studio"),
    OWNER,
)

DESIGNS = {"d1": {"owner_id": "u1"}, "d2": {"owner_id": "someone-else"}}


class FakeAuth(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        who = request.headers.get("x-user")
        if who:
            request.state.current_user = User(id=who, name=who, email=f"{who}@x.org")
        return await call_next(request)


def loader(request, ref):
    return DESIGNS.get(ref.id)


async def build(catalog, *policies, status="active", owner_role="OWN", **abac_kw):
    store = InMemoryAssignmentStore()
    await store.assign(
        NewAssignment(
            "u1", ScopeRef("studio", "s1"), owner_role, {"tenant_status": status}
        )
    )
    await store.assign(
        NewAssignment("u2", ScopeRef("studio", "s1"), "EDI", {"tenant_status": status})
    )
    events: list = []
    config = AbacConfig(policies=StaticPolicySource(policies), **abac_kw)
    authz = Authz.build(
        catalog=catalog,
        store=store,
        abac=config,
        hooks=AuthzHooks(on_decision=events.append),
    )
    app = FastAPI()
    app.add_middleware(FakeAuth)
    scope = ScopeFromPath("studio", "studio_id")

    @app.get(
        "/studios/{studio_id}/designs/{design_id}",
        dependencies=[Depends(require_permission("design.read", scope=scope))],
    )
    async def read(studio_id: str, design_id: str):
        return {"ok": True}

    @app.put(
        "/studios/{studio_id}/designs/{design_id}",
        dependencies=[Depends(require_permission("design.write", scope=scope))],
    )
    async def write(studio_id: str, design_id: str):
        return {"ok": True}

    @app.delete(
        "/studios/{studio_id}/designs/{design_id}",
        openapi_extra=permission_extra("design.delete", abac=True),
        dependencies=[
            Depends(
                require_permission(
                    "design.delete",
                    scope=scope,
                    resource=ResourceFromPath("design", "design_id", loader),
                )
            )
        ],
    )
    async def delete(studio_id: str, design_id: str):
        return {"ok": True}

    @app.get("/studios/{studio_id}/probe/{design_id}")
    async def probe(
        request: Request,
        studio_id: str,
        design_id: str,
    ):
        ok = await has_permission(
            request,
            "design.delete",
            ScopeRef("studio", studio_id),
            resource=ResourceFromPath("design", "design_id", loader),
        )
        return {"allowed": ok}

    authz.install(app)
    return app, authz, events


H1, H2 = {"x-user": "u1"}, {"x-user": "u2"}


@pytest.mark.asyncio
async def test_suspended_studio_blocks_writes_but_not_reads(catalog):
    app, _, events = await build(catalog, SUSPENDED, status="suspended")
    with TestClient(app) as c:
        assert c.get("/studios/s1/designs/d1", headers=H1).status_code == 200
        r = c.put("/studios/s1/designs/d1", headers=H1)
        assert r.status_code == 403
        assert r.json()["detail"] == {
            "error": "forbidden",
            "required_permission": "design.write",
        }
    denied = [e for e in events if e.kind.value == "denied"][0]
    assert denied.policy_ids == ("studio-suspended-readonly",)
    assert denied.abac_reason == "deny:studio-suspended-readonly"
    assert "tenant_status" not in str(denied.to_dict())  # ids only, no values


@pytest.mark.asyncio
async def test_active_studio_allows_everything(catalog):
    app, _, _ = await build(catalog, SUSPENDED, status="active")
    with TestClient(app) as c:
        assert c.put("/studios/s1/designs/d1", headers=H1).status_code == 200


@pytest.mark.asyncio
async def test_owner_only_delete_through_the_loader(catalog):
    app, _, events = await build(catalog, OWNER_ONLY)
    with TestClient(app) as c:
        assert c.delete("/studios/s1/designs/d1", headers=H1).status_code == 200
        assert c.delete("/studios/s1/designs/d2", headers=H1).status_code == 403
        assert c.delete("/studios/s1/designs/nope", headers=H1).status_code == 404
        assert c.get("/studios/s1/probe/d1", headers=H1).json() == {"allowed": True}
        assert c.get("/studios/s1/probe/d2", headers=H1).json() == {"allowed": False}
    assert any(e.policy_ids == ("owner-only-delete",) for e in events)


@pytest.mark.asyncio
async def test_invalid_resource_id_is_not_visible(catalog):
    app, _, _ = await build(catalog, OWNER_ONLY)
    with TestClient(app) as c:
        assert (
            c.delete(f"/studios/s1/designs/{'x' * 300}", headers=H1).status_code == 404
        )


@pytest.mark.asyncio
async def test_hide_policy_answers_404_like_a_stranger(catalog):
    hidden = NewPolicy(
        "hide-it",
        Effect.DENY,
        ("design.write",),
        PolicyScope("studio"),
        {"eq": [STATUS, "suspended"]},
        hide=True,
    )
    app, _, _ = await build(catalog, hidden, status="suspended")
    with TestClient(app) as c:
        mine = c.put("/studios/s1/designs/d1", headers=H1)
        stranger = c.put("/studios/s1/designs/d1", headers={"x-user": "stranger"})
        assert mine.status_code == stranger.status_code == 404
        assert mine.content == stranger.content


@pytest.mark.asyncio
async def test_default_config_wraps_the_source_in_a_5s_cache(catalog):
    _, authz, _ = await build(catalog, SUSPENDED)
    assert isinstance(authz.policy_source, CachingPolicySource)
    _, plain, _ = await build(catalog, SUSPENDED, policy_cache_ttl=0)
    assert isinstance(plain.policy_source, StaticPolicySource)


def test_without_abac_nothing_changes(catalog):
    store = InMemoryAssignmentStore()
    authz = Authz.build(catalog=catalog, store=store)
    assert authz.policy_source is None and authz.abac is None
    assert permission_extra("design.read") == {"x-permission": "design.read"}
    app = FastAPI()
    app.get("/x", openapi_extra=permission_extra("design.read"))(lambda: None)
    assert declared_permissions(app) == {("GET", "/x"): "design.read"}


def test_invalid_static_policies_fail_the_build_listing_everything(catalog):
    bad1 = NewPolicy(
        "b1",
        Effect.DENY,
        ("nope.*",),
        PolicyScope("studio"),
        {"eq": [{"attr": "subject.attrs.ghost"}, 1]},
    )
    bad2 = NewPolicy(
        "b2", Effect.PERMIT, ("design.read",), PolicyScope("studio"), {"eq": [1, 1]}
    )
    with pytest.raises(ConfigurationError) as exc:
        Authz.build(
            catalog=catalog,
            store=InMemoryAssignmentStore(),
            abac=AbacConfig(policies=StaticPolicySource([bad1, bad2])),
        )
    msg = str(exc.value)
    assert "matches nothing" in msg and "ghost" in msg and "mode='grant'" in msg


def test_abac_config_validation(catalog):
    store = InMemoryAssignmentStore()
    src = StaticPolicySource([])
    for cfg in (
        AbacConfig(policies=src, mode="x"),  # type: ignore[arg-type]
        AbacConfig(policies=src, policy_cache_ttl=-1),
        AbacConfig(policies=[]),
    ):
        with pytest.raises(ConfigurationError):
            Authz.build(catalog=catalog, store=store, abac=cfg)
    permit = NewPolicy(
        "g", Effect.PERMIT, ("design.write",), PolicyScope("studio"), {"eq": [1, 1]}
    )
    Authz.build(
        catalog=catalog,
        store=store,
        abac=AbacConfig(policies=StaticPolicySource([permit]), mode="grant"),
    )


@pytest.mark.asyncio
async def test_guard_with_resource_but_no_abac_is_a_startup_error(catalog):
    authz = Authz.build(catalog=catalog, store=InMemoryAssignmentStore())
    app = FastAPI()

    @app.delete(
        "/studios/{studio_id}/designs/{design_id}",
        dependencies=[
            Depends(
                require_permission(
                    "design.delete",
                    scope=ScopeFromPath("studio", "studio_id"),
                    resource=ResourceFromPath("design", "design_id"),
                )
            )
        ],
    )
    async def delete(studio_id: str, design_id: str):
        return {}

    with pytest.raises(ConfigurationError, match="resource="):
        authz.validate_routes(app)


@pytest.mark.asyncio
async def test_duplicate_ids_across_sources_fail_at_startup(catalog):
    store = InMemoryAssignmentStore()
    a = StaticPolicySource([SUSPENDED])
    b = StaticPolicySource([SUSPENDED])
    authz = Authz.build(
        catalog=catalog,
        store=store,
        abac=AbacConfig(policies=[a, b], policy_cache_ttl=0),
    )
    with pytest.raises(ConfigurationError, match="twice"):
        await authz.verify_policies()


@pytest.mark.asyncio
async def test_invalid_stored_policy_denies_through_the_guard(catalog):
    class Junk:
        async def list_policies(self, scope):
            return [
                Policy(
                    "junk",
                    Effect.DENY,
                    ("design.*",),
                    PolicyScope("studio"),
                    {"bogus": [1]},
                )
            ]

        async def list_all(self, status=None):
            return []

    store = InMemoryAssignmentStore()
    await store.assign(NewAssignment("u1", ScopeRef("studio", "s1"), "OWN"))
    authz = Authz.build(
        catalog=catalog,
        store=store,
        abac=AbacConfig(policies=Junk(), policy_cache_ttl=0),
    )
    app = FastAPI()
    app.add_middleware(FakeAuth)

    @app.get(
        "/studios/{studio_id}/x",
        dependencies=[
            Depends(
                require_permission(
                    "design.read", scope=ScopeFromPath("studio", "studio_id")
                )
            )
        ],
    )
    async def x(studio_id: str):
        return {}

    authz.install(app)
    with TestClient(app) as c:
        assert c.get("/studios/s1/x", headers=H1).status_code == 403
