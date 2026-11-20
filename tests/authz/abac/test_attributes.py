"""AUTHZ-026: attribute providers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from auth_middleware.authz import Principal, ScopeRef
from auth_middleware.authz.abac.attributes import (
    AttributeRequest,
    AttributeResolver,
    ContextAttributeProvider,
    EnvironmentProvider,
    ResourceAttributeProvider,
    ResourceContext,
    ResourceRef,
    SubjectAttributeProvider,
)
from auth_middleware.authz.abac.resources import (
    ResourceFromCallable,
    ResourceFromPath,
    ResourceFromQuery,
)
from auth_middleware.authz.abac.types import EntityRef
from auth_middleware.authz.errors import (
    ConfigurationError,
    InvalidScopeError,
    ResourceNotFoundError,
    StoreUnavailableError,
)
from auth_middleware.authz.stores.memory import InMemoryAttributeStore

NOW = datetime(2026, 11, 20, 14, 30, tzinfo=UTC)  # a Friday


def make_request(
    headers=(),
    client=("10.0.0.9", 1234),
    claims=None,
    path_params=None,
    query=b"",
    method="GET",
    path="/x",
):
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query,
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers],
        "client": client,
        "path_params": path_params or {},
    }
    request = Request(scope)
    if claims is not None:
        request.state.current_user = SimpleNamespace(
            _jwt_credentials=SimpleNamespace(claims=claims)
        )
    return request


def ctx(request=None, resource=None, **kw):
    return AttributeRequest(
        principal=kw.pop("principal", Principal("u1", ("g1", "g2"), "u1@x.org")),
        permission="design.write",
        scope=ScopeRef("studio", "s1"),
        roles=frozenset({"EDI"}),
        assignment_attributes=kw.pop(
            "assignment", {"tenant_status": "active", "n": {"d": 1}}
        ),
        resource=resource,
        request=request,
    )


@pytest.mark.asyncio
async def test_context_provider_basics_and_laziness():
    p = ContextAttributeProvider()
    needed = frozenset(
        {
            "subject.id",
            "subject.email",
            "subject.groups",
            "subject.roles",
            "action.permission",
            "subject.assignment.tenant_status",
            "subject.assignment.n.d",
            "subject.assignment.missing",
        }
    )
    got = await p.load(ctx(), needed)
    assert got == {
        "subject.id": "u1",
        "subject.email": "u1@x.org",
        "subject.groups": ["g1", "g2"],
        "subject.roles": ["EDI"],
        "action.permission": "design.write",
        "subject.assignment.tenant_status": "active",
        "subject.assignment.n.d": 1,
    }
    assert await p.load(ctx(), frozenset({"subject.id"})) == {"subject.id": "u1"}


@pytest.mark.asyncio
async def test_context_provider_resource_ref_and_no_email():
    p = ContextAttributeProvider()
    c = ctx(
        principal=Principal("u1"), resource=ResourceContext(ResourceRef("design", "d1"))
    )
    got = await p.load(c, frozenset({"resource.kind", "resource.id", "subject.email"}))
    assert got == {"resource.kind": "design", "resource.id": "d1"}


@pytest.mark.asyncio
async def test_claims_only_through_the_allowlist():
    claims = {
        "dept": "eng",
        "custom:department": "ops",
        "secret": "s",
        "nest": {"a": 1},
    }
    request = make_request(claims=claims)
    needed = frozenset(
        {
            "subject.claims.dept",
            "subject.claims.secret",
            "subject.claims.dept2",
            "subject.claims.nest.a",
        }
    )
    plain = ContextAttributeProvider(["dept"])
    assert await plain.load(ctx(request), needed) == {"subject.claims.dept": "eng"}
    mapped = ContextAttributeProvider({"dept2": "custom:department", "nest": "nest"})
    got = await mapped.load(ctx(request), needed)
    assert got == {"subject.claims.dept2": "ops", "subject.claims.nest.a": 1}
    assert await ContextAttributeProvider().load(ctx(request), needed) == {}
    assert await plain.load(ctx(make_request()), needed) == {}
    with pytest.raises(ConfigurationError):
        ContextAttributeProvider({"bad-name": "x"})


@pytest.mark.asyncio
async def test_hostile_claim_values_are_dropped():
    request = make_request(
        claims={"dept": object(), "ok": "y", "big": list(range(500))}
    )
    p = ContextAttributeProvider(["dept", "ok", "big"])
    got = await p.load(
        ctx(request),
        frozenset({"subject.claims.dept", "subject.claims.ok", "subject.claims.big"}),
    )
    assert got == {"subject.claims.ok": "y"}


@pytest.mark.asyncio
async def test_subject_attributes_from_store():
    store = InMemoryAttributeStore()
    await store.put_attributes(
        EntityRef.principal("u1"),
        {"clearance": 3, "tags": ["a"]},
        expected_revision=None,
    )
    p = SubjectAttributeProvider(store)
    got = await p.load(
        ctx(), frozenset({"subject.attrs.clearance", "subject.attrs.nope"})
    )
    assert got == {"subject.attrs.clearance": 3}
    assert (
        await SubjectAttributeProvider(None).load(ctx(), frozenset({"subject.attrs.x"}))
        == {}
    )
    other = ctx(principal=Principal("nobody"))
    assert await p.load(other, frozenset({"subject.attrs.clearance"})) == {}


class _Boom:
    async def get_attributes(self, ref):
        raise RuntimeError("db down")


@pytest.mark.asyncio
async def test_store_failures_are_unavailable():
    with pytest.raises(StoreUnavailableError):
        await SubjectAttributeProvider(_Boom()).load(
            ctx(), frozenset({"subject.attrs.x"})
        )
    res = ResourceContext(ResourceRef("design", "d1"))
    with pytest.raises(StoreUnavailableError):
        await ResourceAttributeProvider(_Boom()).load(
            ctx(resource=res), frozenset({"resource.attrs.x"})
        )


@pytest.mark.asyncio
async def test_resource_loader_paths():
    calls = []

    async def loader(request, ref):
        calls.append(ref)
        return {"owner_id": "u1", "n": 3, "huge": list(range(500)), "bad key": 1}

    res = ResourceContext(ResourceRef("design", "d1"), loader)
    p = ResourceAttributeProvider()
    got = await p.load(
        ctx(resource=res),
        frozenset(
            {"resource.attrs.owner_id", "resource.attrs.huge", "resource.attrs.n"}
        ),
    )
    assert got == {"resource.attrs.owner_id": "u1", "resource.attrs.n": 3}
    assert calls == [ResourceRef("design", "d1")]

    sync = ResourceContext(ResourceRef("design", "d1"), lambda r, ref: {"a": 1})
    assert await p.load(ctx(resource=sync), frozenset({"resource.attrs.a"})) == {
        "resource.attrs.a": 1
    }
    assert await p.load(ctx(), frozenset({"resource.attrs.a"})) == {}


@pytest.mark.asyncio
async def test_resource_loader_none_means_not_found_and_errors_mean_unavailable():
    p = ResourceAttributeProvider()
    gone = ResourceContext(ResourceRef("design", "d1"), lambda r, ref: None)
    with pytest.raises(ResourceNotFoundError):
        await p.load(ctx(resource=gone), frozenset({"resource.attrs.a"}))

    def raises(r, ref):
        raise ValueError("boom")

    with pytest.raises(StoreUnavailableError):
        await p.load(
            ctx(resource=ResourceContext(ResourceRef("d", "1"), raises)),
            frozenset({"resource.attrs.a"}),
        )
    with pytest.raises(StoreUnavailableError):
        await p.load(
            ctx(resource=ResourceContext(ResourceRef("d", "1"), lambda r, f: [1])),
            frozenset({"resource.attrs.a"}),
        )


@pytest.mark.asyncio
async def test_resource_attributes_from_store_when_no_loader():
    store = InMemoryAttributeStore()
    await store.put_attributes(
        EntityRef("resource", "design", "d1"),
        {"classification": 2},
        expected_revision=None,
    )
    p = ResourceAttributeProvider(store)
    res = ResourceContext(ResourceRef("design", "d1"))
    assert await p.load(
        ctx(resource=res), frozenset({"resource.attrs.classification"})
    ) == {"resource.attrs.classification": 2}
    unknown = ResourceContext(ResourceRef("design", "other"))
    assert (
        await p.load(
            ctx(resource=unknown), frozenset({"resource.attrs.classification"})
        )
        == {}
    )


@pytest.mark.asyncio
async def test_environment_time_and_request():
    p = EnvironmentProvider(clock=lambda: NOW)
    needed = frozenset(
        {"env.now", "env.hour_utc", "env.weekday", "env.method", "env.path", "env.ip"}
    )
    got = await p.load(ctx(make_request(method="POST", path="/api/x")), needed)
    assert got == {
        "env.now": NOW,
        "env.hour_utc": 14,
        "env.weekday": 4,
        "env.method": "POST",
        "env.path": "/api/x",
        "env.ip": "10.0.0.9",
    }
    only_time = await p.load(ctx(None), needed)
    assert set(only_time) == {"env.now", "env.hour_utc", "env.weekday"}
    naive = EnvironmentProvider(clock=lambda: datetime(2026, 1, 1))
    assert await naive.load(ctx(None), needed) == {}


@pytest.mark.asyncio
async def test_forwarded_for_is_only_believed_from_trusted_proxies():
    headers = [("x-forwarded-for", "6.6.6.6, 203.0.113.7, 10.0.0.5")]
    needed = frozenset({"env.ip"})
    untrusted = EnvironmentProvider()
    assert await untrusted.load(
        ctx(make_request(headers, client=("8.8.8.8", 1))), needed
    ) == {"env.ip": "8.8.8.8"}
    trusted = EnvironmentProvider(trusted_proxies=["10.0.0.0/8"])
    spoof = make_request(headers, client=("8.8.8.8", 1))  # peer is not a proxy
    assert await trusted.load(ctx(spoof), needed) == {"env.ip": "8.8.8.8"}
    behind = make_request(headers, client=("10.0.0.7", 1))
    assert await trusted.load(ctx(behind), needed) == {"env.ip": "203.0.113.7"}
    garbage = make_request([("x-forwarded-for", "not-an-ip")], client=("10.0.0.7", 1))
    assert await trusted.load(ctx(garbage), needed) == {}
    assert await trusted.load(ctx(make_request(client=None)), needed) == {}
    all_trusted = make_request(
        [("x-forwarded-for", "10.1.1.1")], client=("10.0.0.7", 1)
    )
    assert await trusted.load(ctx(all_trusted), needed) == {"env.ip": "10.0.0.7"}
    with pytest.raises(ConfigurationError):
        EnvironmentProvider(trusted_proxies=["nope"])


@pytest.mark.asyncio
async def test_headers_only_from_the_allowlist_and_never_duplicated():
    p = EnvironmentProvider(headers_allowlist=["X_Tenant"])
    needed = frozenset({"env.header.x_tenant", "env.header.authorization"})
    one = make_request([("X-Tenant", "t1"), ("Authorization", "Bearer s")])
    assert await p.load(ctx(one), needed) == {"env.header.x_tenant": "t1"}
    two = make_request([("X-Tenant", "t1"), ("x-tenant", "t2")])
    assert await p.load(ctx(two), needed) == {}


class _Spy:
    prefixes = ("env.",)

    def __init__(self):
        self.calls = 0

    async def load(self, c, needed):
        self.calls += 1
        return {"env.now": 1, "subject.id": "intruder"}


@pytest.mark.asyncio
async def test_resolver_is_lazy_filters_answers_and_checks_overlap():
    spy = _Spy()
    resolver = AttributeResolver([ContextAttributeProvider(), spy])
    got = await resolver.resolve(ctx(), {"subject.id"})
    assert got == {"subject.id": "u1"} and spy.calls == 0
    got = await resolver.resolve(ctx(), {"env.now", "subject.id"})
    assert got == {"subject.id": "u1", "env.now": 1} and spy.calls == 1  # no injection
    with pytest.raises(ConfigurationError):
        AttributeResolver(
            [
                ContextAttributeProvider(),
                SubjectAttributeProvider(),
                SubjectAttributeProvider(),
            ]
        )
    clash = SimpleNamespace(prefixes=("subject.id",), load=None)
    with pytest.raises(ConfigurationError):
        AttributeResolver([ContextAttributeProvider(), clash])  # type: ignore[list-item]


@pytest.mark.asyncio
async def test_resolver_turns_provider_crashes_into_unavailable():
    class Crash:
        prefixes = ("env.",)

        async def load(self, c, needed):
            raise RuntimeError("x")

    with pytest.raises(StoreUnavailableError):
        await AttributeResolver([Crash()]).resolve(ctx(), {"env.now"})


@pytest.mark.asyncio
async def test_default_resolver_calls_a_loader_once_for_many_paths():
    calls = []

    def loader(request, ref):
        calls.append(1)
        return {"a": 1, "b": 2, "c": 3}

    resolver = AttributeResolver.default(clock=lambda: NOW)
    res = ResourceContext(ResourceRef("design", "d1"), loader)
    got = await resolver.resolve(
        ctx(resource=res), {"resource.attrs.a", "resource.attrs.b", "resource.attrs.c"}
    )
    assert got == {"resource.attrs.a": 1, "resource.attrs.b": 2, "resource.attrs.c": 3}
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_resource_sources():
    req = make_request(path_params={"d": "abc"}, query=b"id=q1&x=1")
    assert await ResourceFromPath("design", "d").resolve(req) == ResourceRef(
        "design", "abc"
    )
    assert await ResourceFromQuery("design", "id").resolve(req) == ResourceRef(
        "design", "q1"
    )
    assert await ResourceFromCallable("design", lambda r: "z").resolve(
        req
    ) == ResourceRef("design", "z")

    async def acall(r):
        return "async-id"

    assert (await ResourceFromCallable("design", acall).resolve(req)).id == "async-id"
    with pytest.raises(ConfigurationError):
        await ResourceFromPath("design", "missing").resolve(req)
    with pytest.raises(InvalidScopeError):
        await ResourceFromQuery("design", "absent").resolve(req)
    long_req = make_request(path_params={"d": "x" * 300})
    with pytest.raises(InvalidScopeError):
        await ResourceFromPath("design", "d").resolve(long_req)
    with pytest.raises(InvalidScopeError):
        await ResourceFromCallable("Bad Kind", lambda r: "x").resolve(req)


def test_timedelta_import_used():
    assert NOW + timedelta(1) > NOW
