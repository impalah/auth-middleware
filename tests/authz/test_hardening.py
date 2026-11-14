"""Regression tests for the issues found by the 0.7.0 quality review (authz)."""

from __future__ import annotations

import asyncio

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from starlette.middleware.base import BaseHTTPMiddleware

from auth_middleware.authz import (
    AssignmentService,
    AssignmentStatus,
    Authorizer,
    Authz,
    CachingAssignmentStore,
    ConfigurationError,
    NewAssignment,
    Principal,
    ScopeFromCallable,
    ScopeFromPath,
    ScopeRef,
    StoreUnavailableError,
    require_permission,
)
from auth_middleware.authz.stores import InMemoryAssignmentStore, SqlAssignmentStore
from auth_middleware.authz.stores.sql import _is_duplicate_key
from auth_middleware.types.user import User

S = ScopeRef("studio", "s1")


class Auth(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        who = request.headers.get("x-user")
        if who is not None:
            request.state.current_user = User(id=who, name="n", groups=[])
        return await call_next(request)


def _client(catalog, store=None, store_factory=None, **kw) -> TestClient:
    app = FastAPI()
    app.add_middleware(Auth)
    Authz.build(
        catalog=catalog,
        store=store,
        store_factory=store_factory,
        group_roles={"admins": "OWNER"}
        if store is None and store_factory is None
        else None,
        **kw,
    ).install(app)

    @app.get("/s/{sid}")
    async def read(
        sid: str,
        ctx=Depends(
            require_permission("design.read", scope=ScopeFromPath("studio", "sid"))
        ),
    ):
        return {}

    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def seeded():
    store = InMemoryAssignmentStore()
    asyncio.run(store.assign(NewAssignment("u1", S, "READER")))
    asyncio.run(store.assign(NewAssignment("ghost", S, "REMOVED-FROM-CATALOG")))
    return store


def test_a_role_that_left_the_catalog_denies_instead_of_500(catalog, seeded):
    client = _client(catalog, seeded)
    assert client.get("/s/s1", headers={"x-user": "u1"}).status_code == 200
    r = client.get("/s/s1", headers={"x-user": "ghost"})
    assert r.status_code == 403
    assert r.json()["detail"]["required_permission"] == "design.read"


@pytest.mark.asyncio
async def test_an_unknown_role_does_not_break_other_valid_roles(catalog, seeded):
    class Both:
        async def resolve(self, principal, scope):
            from auth_middleware.authz import ResolvedRoles

            return ResolvedRoles(frozenset({"READER", "GONE"}))

    authorizer = Authorizer(catalog, [Both()])
    ctx = await authorizer.authorize(Principal("x"), "design.read", S)
    assert ctx.roles == {"READER"}


@pytest.mark.parametrize("scope_id", ["x" * 201, "*"])
def test_invalid_scope_ids_answer_like_unknown_scopes(catalog, seeded, scope_id):
    client = _client(catalog, seeded)
    unknown = client.get("/s/never-existed", headers={"x-user": "u1"})
    invalid = client.get(f"/s/{scope_id}", headers={"x-user": "u1"})
    assert unknown.status_code == invalid.status_code == 404
    assert unknown.json() == invalid.json()


def test_scope_from_callable_invalid_id_is_also_not_visible(catalog, seeded):
    app = FastAPI()
    app.add_middleware(Auth)
    Authz.build(catalog=catalog, store=seeded).install(app)

    @app.get("/c")
    async def c(
        ctx=Depends(
            require_permission(
                "design.read", scope=ScopeFromCallable("studio", lambda r: "y" * 999)
            )
        ),
    ):
        return {}

    assert TestClient(app).get("/c", headers={"x-user": "u1"}).status_code == 404


def test_an_empty_principal_id_is_unauthenticated(catalog, seeded):
    r = _client(catalog, seeded).get("/s/s1", headers={"x-user": ""})
    assert r.status_code == 401


def test_a_store_outage_is_503_not_500(catalog):
    class Down:
        async def get_assignment(self, principal_id, scope):
            raise StoreUnavailableError("throttled")

        async def list_assignments(self, principal_id):
            return []

    r = _client(catalog, Down()).get("/s/s1", headers={"x-user": "u1"})
    assert r.status_code == 503 and r.headers["retry-after"] == "1"


@pytest.mark.asyncio
async def test_cache_does_not_store_a_read_that_raced_a_revocation():
    release = asyncio.Event()
    started = asyncio.Event()

    class Slow(InMemoryAssignmentStore):
        async def get_assignment(self, principal_id, scope):
            value = await super().get_assignment(principal_id, scope)  # pre-write view
            started.set()
            await release.wait()
            return value

    inner = Slow()
    cache = CachingAssignmentStore(inner, ttl_seconds=30)
    first = await inner.assign(NewAssignment("u", S, "R"))
    reader = asyncio.create_task(cache.get_assignment("u", S))
    await started.wait()
    await cache.revoke("u", S, expected_revision=first.revision)  # invalidates
    release.set()
    await reader
    # the stale pre-revocation value must not have been cached
    release.set()
    fresh = await cache.get_assignment("u", S)
    assert fresh is not None and fresh.status is AssignmentStatus.REVOKED


@pytest.mark.asyncio
async def test_cache_aclose_accepts_a_sync_close():
    closed = []

    class Inner(InMemoryAssignmentStore):
        def aclose(self):
            closed.append(1)

    await CachingAssignmentStore(Inner(), ttl_seconds=5).aclose()
    assert closed == [1]


@pytest.mark.asyncio
async def test_memory_store_attributes_cannot_be_mutated_through_a_result():
    store = InMemoryAssignmentStore()
    got = await store.assign(NewAssignment("u", S, "R", {"k": "v"}))
    with pytest.raises(TypeError):
        got.attributes["k"] = "tampered"  # type: ignore[index]
    again = await store.get_assignment("u", S)
    assert dict(again.attributes) == {"k": "v"}


@pytest.mark.asyncio
async def test_every_after_change_hook_runs_even_if_one_fails(catalog):
    store = InMemoryAssignmentStore()
    ran = []

    async def bad(change, written):
        raise RuntimeError("hook failed")

    async def invalidate(change, written):
        ran.append(written.role)

    service = AssignmentService(store, catalog, after_change=[bad, invalidate])
    with pytest.raises(RuntimeError):
        await service.assign("u", S, "READER")
    assert ran == ["READER"]  # the write happened and later hooks were not skipped


def test_sql_commit_false_needs_an_injected_session():
    with pytest.raises(ConfigurationError):
        SqlAssignmentStore(lambda: None, commit=False)


def test_only_duplicate_keys_are_revision_conflicts():
    class Orig(Exception):
        pass

    assert _is_duplicate_key(
        IntegrityError("s", {}, Orig("UNIQUE constraint failed: t.c"))
    )
    assert _is_duplicate_key(
        IntegrityError("s", {}, Orig("Duplicate entry 'x' for key"))
    )
    assert _is_duplicate_key(
        IntegrityError("s", {}, Orig("violates unique constraint"))
    )
    assert not _is_duplicate_key(
        IntegrityError("s", {}, Orig("CHECK constraint failed: status"))
    )
    assert not _is_duplicate_key(
        IntegrityError("s", {}, Orig("NOT NULL constraint failed"))
    )


@pytest.mark.asyncio
async def test_dynamodb_connection_errors_map_to_unavailable():
    pytest.importorskip("pynamodb")
    from pynamodb.exceptions import PynamoDBConnectionError

    from auth_middleware.authz.stores import DynamoDbAssignmentStore

    store = DynamoDbAssignmentStore(table_name="t", region="us-east-1")

    def boom(*a, **k):
        raise PynamoDBConnectionError("cannot connect")

    store._item.get = boom
    with pytest.raises(StoreUnavailableError):
        await store.get_assignment("u", S)


@pytest.mark.asyncio
async def test_last_owner_rule_holds_under_concurrent_requests_in_one_process(catalog):
    """Two owners revoking each other at once must not both pass the veto check."""
    store = InMemoryAssignmentStore()
    a = await store.assign(NewAssignment("o1", S, "OWNER"))
    b = await store.assign(NewAssignment("o2", S, "OWNER"))

    class LastOwner(Exception):
        pass

    async def last_owner(change):
        if change.kind != "revoke":
            return
        await asyncio.sleep(0.01)  # a wide check-then-act window
        owners = [
            x
            for x in await store.list_for_scope(change.scope)
            if x.role == "OWNER" and x.status is AssignmentStatus.ACTIVE
        ]
        if len(owners) <= 1:
            raise LastOwner

    service = AssignmentService(store, catalog, before_change=[last_owner])
    results = await asyncio.gather(
        service.revoke("o1", S, expected_revision=a.revision),
        service.revoke("o2", S, expected_revision=b.revision),
        return_exceptions=True,
    )
    assert sum(isinstance(r, LastOwner) for r in results) == 1
    active = [
        x for x in await store.list_for_scope(S) if x.status is AssignmentStatus.ACTIVE
    ]
    assert len(active) == 1  # a scope never ends up without an owner


@pytest.mark.asyncio
async def test_dynamodb_dedicated_pool_is_used_and_closed():
    pytest.importorskip("pynamodb")
    import threading

    from auth_middleware.authz.stores import DynamoDbAssignmentStore

    store = DynamoDbAssignmentStore(table_name="t", region="us-east-1", max_workers=2)
    threads: list[str] = []

    def fake_get(*a, **k):
        threads.append(threading.current_thread().name)
        raise store._item.DoesNotExist()

    store._item.get = fake_get
    assert await store.get_assignment("u", S) is None
    assert threads[0].startswith("authz-dynamodb")
    await store.aclose()
