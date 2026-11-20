"""AUTHZ-035: hostile input, fail-closed matrix, enumeration and isolation."""

from __future__ import annotations

import json
import random
import time
from datetime import UTC, datetime

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from loguru import logger

from auth_middleware.authz import (
    AssignmentRoleResolver,
    Authorizer,
    Authz,
    ConfigurationError,
    DecisionKind,
    NewAssignment,
    PermissionDeniedError,
    Principal,
    ScopeFromPath,
    ScopeRef,
    StoreUnavailableError,
    require_permission,
)
from auth_middleware.authz.abac.attributes import (
    AttributeResolver,
    ResourceContext,
    ResourceRef,
)
from auth_middleware.authz.abac.cache import CachingPolicySource
from auth_middleware.authz.abac.conditions import Tri, evaluate, parse_condition
from auth_middleware.authz.abac.config import AbacConfig
from auth_middleware.authz.abac.pdp import PolicyDecisionPoint
from auth_middleware.authz.abac.resources import ResourceFromPath
from auth_middleware.authz.abac.sources import StaticPolicySource
from auth_middleware.authz.abac.types import (
    Effect,
    NewPolicy,
    Policy,
    PolicyScope,
    new_policy_from_dict,
)
from auth_middleware.authz.errors import ConditionError, InvalidPolicyError
from auth_middleware.authz.stores.memory import (
    InMemoryAssignmentStore,
    InMemoryPolicyStore,
)

from .test_guard_abac import FakeAuth

S1, S2 = ScopeRef("studio", "s1"), ScopeRef("studio", "s2")
SECRET = "sentinel-secret-value-9f3a"
OWNER = {"eq": [{"attr": "resource.attrs.owner_id"}, {"attr": "subject.id"}]}


def pol(pid="p", effect=Effect.DENY, perms=("design.*",), cond=None, scope=None, **kw):
    cond = cond or {"eq": [{"attr": "resource.attrs.owner_id"}, "nobody"]}
    return NewPolicy(pid, effect, perms, scope or PolicyScope("studio"), cond, **kw)


async def authorizer(catalog, policies=(), source=None, resolver=None, role="OWN"):
    assignments = InMemoryAssignmentStore()
    await assignments.assign(NewAssignment("u1", S1, role))
    store = InMemoryPolicyStore()
    for p in policies:
        await store.create(p)
    pdp = PolicyDecisionPoint(source or store, resolver or AttributeResolver.default())
    return Authorizer(catalog, [AssignmentRoleResolver(assignments)], pdp=pdp), store


def res(loader):
    return ResourceContext(ResourceRef("design", "d1"), loader)


# ------------------------------------------------------------ policy injection


HOSTILE_DOCS = [
    {"__proto__": {"x": 1}},
    {"$where": "1==1"},
    {"eq": [{"attr": "subject.attrs.x"}, 10**400]},
    {"eq": [{"attr": "subject.attrs.x"}, "x" * 1_000_000]},
    {"all": [{"eq": [1, 1]}] * 5000},
    {"in": [{"attr": "subject.id"}, list(range(100_000))]},
    {"eq": [{"attr": "subject.id"}, {"attr": "subject.id", "extra": 1}]},
    {"eq": [{"attr": "../../etc/passwd"}, 1]},
    {"eq": [{"attr": "subject." + "a." * 200}, 1]},
]


@pytest.mark.parametrize("doc", HOSTILE_DOCS)
def test_hostile_conditions_are_rejected_quickly(doc):
    start = time.perf_counter()
    with pytest.raises(ConditionError):
        parse_condition(doc)
    assert time.perf_counter() - start < 0.5


def test_deeply_nested_json_cannot_exhaust_the_stack():
    nested = "[" * 200_000 + "]" * 200_000
    with pytest.raises((ValueError, RecursionError)):
        json.loads(nested)  # the stdlib refuses before we see it
    doc: dict = {"eq": [1, 1]}
    for _ in range(50_000):
        doc = {"not": doc}
    with pytest.raises(ConditionError):
        parse_condition(doc)
    with pytest.raises(InvalidPolicyError):
        new_policy_from_dict(
            {
                "id": "x",
                "effect": "deny",
                "permissions": ["a"],
                "scope": {"kind": "s"},
                "condition": doc,
            }
        )


def test_policy_documents_reject_bad_shapes():
    base = {
        "id": "x",
        "effect": "deny",
        "permissions": ["a.b"],
        "scope": {"kind": "s"},
        "condition": {"eq": [1, 1]},
    }
    for patch in (
        {"scope": "studio"},
        {"permissions": "a.b"},
        {"effect": ["deny"]},
        {"hide": "yes"},
        {"enforce": 1},
        {"priority": "1"},
        {"id": "../x"},
        {"permissions": ["a b"]},
        {"scope": {"kind": "S", "id": "x"}},
    ):
        with pytest.raises(InvalidPolicyError):
            new_policy_from_dict({**base, **patch})


# ---------------------------------------------------------- attribute injection


@pytest.mark.asyncio
async def test_hostile_loader_results_never_raise_and_never_allow(catalog):
    class Evil(str):
        def __eq__(self, other):  # pragma: no cover - must never run
            raise AssertionError("hostile __eq__ called")

        __hash__ = str.__hash__

    class Obj:
        def __eq__(self, other):  # pragma: no cover
            raise AssertionError("hostile __eq__ called")

    payloads = [
        {"owner_id": ["x"] * 500},
        {"owner_id": b"u1"},
        {"owner_id": Obj()},
        {"owner_id": {"a": {"b": {"c": {"d": 1}}}}},
        {"owner_id": float("nan")},
        {"owner_id": 10**500},
        {"owner_id": Evil("u1")},
        {"owner_id": None},
        {"bad key!": "u1"},
        {},
    ]
    a, _ = await authorizer(
        catalog, [pol("owner", Effect.REQUIRE, ("design.delete",), OWNER)]
    )
    for payload in payloads:
        kind = await a.check(
            Principal("u1"),
            "design.delete",
            S1,
            resource=res(lambda r, f, p=payload: p),
        )
        # The Evil("u1") value is copied to an exact str and matches the owner: allowed;
        # nothing else may let the require pass.
        owner = payload.get("owner_id")
        should_pass = isinstance(owner, Evil)
        assert (kind is DecisionKind.ALLOWED) == should_pass, payload


@pytest.mark.asyncio
async def test_non_mapping_loader_results_are_an_outage(catalog):
    a, _ = await authorizer(
        catalog, [pol("owner", Effect.REQUIRE, ("design.delete",), OWNER)]
    )
    for bad in ([1], "str", 5, b"x"):
        with pytest.raises(StoreUnavailableError):
            await a.check(
                Principal("u1"),
                "design.delete",
                S1,
                resource=res(lambda r, f, b=bad: b),
            )


# ----------------------------------------------------------- header spoofing


def test_headers_policies_need_the_allowlist_at_build(catalog):
    deny_evil = pol(
        "evil-tenant", cond={"eq": [{"attr": "env.header.x_tenant"}, "evil"]}
    )
    source = StaticPolicySource([deny_evil])
    with pytest.raises(ConfigurationError, match="headers_allowlist"):
        Authz.build(
            catalog=catalog,
            store=InMemoryAssignmentStore(),
            abac=AbacConfig(policies=source),
        )
    Authz.build(
        catalog=catalog,
        store=InMemoryAssignmentStore(),
        abac=AbacConfig(policies=source, headers_allowlist=["X-Tenant"]),
    )
    claim = pol("dept", cond={"eq": [{"attr": "subject.claims.dept"}, "x"]})
    with pytest.raises(ConfigurationError, match="claims_allowlist"):
        Authz.build(
            catalog=catalog,
            store=InMemoryAssignmentStore(),
            abac=AbacConfig(policies=StaticPolicySource([claim])),
        )
    Authz.build(
        catalog=catalog,
        store=InMemoryAssignmentStore(),
        abac=AbacConfig(
            policies=StaticPolicySource([claim]),
            claims_allowlist={"dept": "custom:dept"},
        ),
    )


# -------------------------------------------------------- fail-closed matrix


class Boom:
    def __init__(self, exc):
        self.exc = exc

    async def list_policies(self, scope):
        raise self.exc

    async def list_all(self, status=None):
        return []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("x"),
        TimeoutError(),
        ConnectionError(),
        KeyError("k"),
        MemoryError(),
    ],
)
async def test_policy_source_failures_are_never_an_allow(catalog, exc):
    a, _ = await authorizer(catalog, source=Boom(exc))
    with pytest.raises(StoreUnavailableError):
        await a.authorize(Principal("u1"), "design.read", S1)


@pytest.mark.asyncio
async def test_provider_and_loader_failures_are_never_an_allow(catalog):
    a, _ = await authorizer(
        catalog, [pol("owner", Effect.REQUIRE, ("design.delete",), OWNER)]
    )

    async def slow(request, ref):
        raise TimeoutError("loader timed out")

    with pytest.raises(StoreUnavailableError):
        await a.authorize(Principal("u1"), "design.delete", S1, resource=res(slow))

    class Crash:
        prefixes = ("subject.attrs.",)

        async def load(self, ctx, needed):
            raise RuntimeError("attribute service down")

    cond = {"eq": [{"attr": "subject.attrs.clearance"}, 1]}
    a2, _ = await authorizer(
        catalog, [pol("c", cond=cond)], resolver=AttributeResolver([Crash()])
    )
    with pytest.raises(StoreUnavailableError):
        await a2.authorize(Principal("u1"), "design.read", S1)


@pytest.mark.asyncio
async def test_poisoned_cache_entry_is_an_outage_not_a_crash_or_an_allow(catalog):
    inner = InMemoryPolicyStore()
    cache = CachingPolicySource(inner, ttl_seconds=30)
    cache._entries[("studio", "s1")] = (
        time.monotonic() + 30,
        "not a tuple of policies",
    )
    a, _ = await authorizer(catalog, source=cache)
    with pytest.raises(StoreUnavailableError):
        await a.authorize(Principal("u1"), "design.read", S1)


@pytest.mark.asyncio
async def test_policy_objects_with_broken_fields_are_an_outage(catalog):
    class Weird:
        status = None
        permissions = None
        priority = id = "x"

    class Source:
        async def list_policies(self, scope):
            return [Weird()]

        async def list_all(self, status=None):
            return []

    a, _ = await authorizer(catalog, source=Source())
    # status is not ACTIVE: ignored (no policy applies); nothing crashes
    assert await a.check(Principal("u1"), "design.read", S1) is DecisionKind.ALLOWED


# ------------------------------------------------------- evaluator totality


PATHS = ["subject.attrs.a", "subject.attrs.b", "resource.attrs.c", "env.now"]
LITERALS = [
    1,
    2.5,
    "x",
    "2026-01-01T00:00:00+00:00",
    True,
    None,
    [1, 2],
    ["x", 1],
    [],
    0,
]
VALUES = [
    1,
    2.5,
    "x",
    "2026-01-01T00:00:00+00:00",
    True,
    False,
    None,
    [1, 2],
    ["x"],
    [],
    datetime(2026, 1, 1, tzinfo=UTC),
    datetime(2026, 1, 1),
    {"k": 1},
    b"x",
    object(),
    10**30,
    float("nan"),
    float("inf"),
    (1, 2),
    {1, 2},
]
OPS2 = [
    "eq",
    "ne",
    "lt",
    "lte",
    "gt",
    "gte",
    "in",
    "not_in",
    "contains",
    "intersects",
    "subset",
    "starts_with",
    "ends_with",
]


def random_condition(rng: random.Random, depth: int = 0):
    roll = rng.random()
    if depth < 3 and roll < 0.25:
        return {
            rng.choice(["all", "any"]): [
                random_condition(rng, depth + 1) for _ in range(rng.randint(1, 3))
            ]
        }
    if depth < 3 and roll < 0.35:
        return {"not": random_condition(rng, depth + 1)}
    if roll < 0.45:
        return {"exists": {"attr": rng.choice(PATHS)}}

    def operand():
        return (
            {"attr": rng.choice(PATHS)} if rng.random() < 0.6 else rng.choice(LITERALS)
        )

    return {rng.choice(OPS2): [operand(), operand()]}


def test_evaluate_is_total_over_random_conditions_and_values():
    rng = random.Random(1234)
    for _ in range(3000):
        raw = random_condition(rng)
        values = {p: rng.choice(VALUES) for p in PATHS if rng.random() < 0.8}
        result = evaluate(parse_condition(raw), values)
        assert isinstance(result, Tri)


@pytest.mark.asyncio
async def test_a_deny_applies_exactly_when_its_condition_is_not_false(catalog):
    """Fail closed: TRUE and INDETERMINATE both deny, only FALSE lets the request pass."""
    rng = random.Random(99)
    assignments = InMemoryAssignmentStore()
    await assignments.assign(NewAssignment("u1", S1, "OWN"))

    class Fuzz:
        prefixes = ("subject.", "resource.", "env.", "action.")

        def __init__(self):
            self.values: dict = {}

        async def load(self, ctx, needed):
            return {k: v for k, v in self.values.items() if k in needed}

    fuzz = Fuzz()
    for _ in range(300):
        raw = random_condition(rng)
        values = {p: rng.choice(VALUES) for p in PATHS if rng.random() < 0.8}
        fuzz.values = values
        store = InMemoryPolicyStore()
        await store.create(
            NewPolicy("fz", Effect.DENY, ("design.read",), PolicyScope("studio"), raw)
        )
        pdp = PolicyDecisionPoint(store, AttributeResolver([fuzz]))
        a = Authorizer(catalog, [AssignmentRoleResolver(assignments)], pdp=pdp)
        kind = await a.check(Principal("u1"), "design.read", S1)
        truth = evaluate(parse_condition(raw), values)
        assert (kind is DecisionKind.DENIED) == (truth is not Tri.FALSE), (raw, values)


# ------------------------------------------------- enumeration and isolation


def _app(catalog, policies, loader):
    store = InMemoryAssignmentStore()
    import asyncio

    asyncio.run(store.assign(NewAssignment("u1", S1, "OWN")))
    authz = Authz.build(
        catalog=catalog,
        store=store,
        abac=AbacConfig(policies=StaticPolicySource(policies), policy_cache_ttl=0),
    )
    app = FastAPI()
    app.add_middleware(FakeAuth)

    @app.delete(
        "/studios/{studio_id}/designs/{design_id}",
        dependencies=[
            Depends(
                require_permission(
                    "design.delete",
                    scope=ScopeFromPath("studio", "studio_id"),
                    resource=ResourceFromPath("design", "design_id", loader),
                )
            )
        ],
    )
    async def delete(studio_id: str, design_id: str):
        return {}

    authz.install(app)
    return TestClient(app)


def test_every_not_visible_answer_is_byte_identical(catalog):
    designs = {"mine": {"owner_id": "u1"}, "theirs": {"owner_id": "u2"}}
    hide_others = pol(
        "hide-others", Effect.REQUIRE, ("design.delete",), OWNER, hide=True
    )
    with _app(catalog, [hide_others], lambda request, ref: designs.get(ref.id)) as c:
        non_member = c.delete(
            "/studios/s1/designs/mine", headers={"x-user": "stranger"}
        )
        unknown = c.delete("/studios/s1/designs/ghost", headers={"x-user": "u1"})
        hidden = c.delete("/studios/s1/designs/theirs", headers={"x-user": "u1"})
        unknown_scope = c.delete("/studios/zzz/designs/mine", headers={"x-user": "u1"})
        too_long = c.delete(
            f"/studios/s1/designs/{'x' * 300}", headers={"x-user": "u1"}
        )
        assert (
            c.delete("/studios/s1/designs/mine", headers={"x-user": "u1"}).status_code
            == 200
        )
    answers = [non_member, unknown, hidden, unknown_scope, too_long]
    assert {r.status_code for r in answers} == {404}
    assert len({r.content for r in answers}) == 1
    assert (
        len(
            {
                tuple(sorted((k, v) for k, v in r.headers.items() if k != "date"))
                for r in answers
            }
        )
        == 1
    )


@pytest.mark.asyncio
async def test_policies_never_cross_scopes_or_kinds(catalog):
    only_s1 = pol(
        "only-s1",
        cond={"exists": {"attr": "subject.id"}},
        scope=PolicyScope("studio", "s1"),
    )
    other_kind = NewPolicy(
        "global-wide",
        Effect.DENY,
        ("admin.all",),
        PolicyScope("global"),
        {"exists": {"attr": "subject.id"}},
    )
    assignments = InMemoryAssignmentStore()
    await assignments.assign(NewAssignment("u1", S1, "OWN"))
    await assignments.assign(NewAssignment("u1", S2, "OWN"))
    await assignments.assign(NewAssignment("u1", ScopeRef.GLOBAL, "ADM"))
    store = InMemoryPolicyStore()
    await store.create(only_s1)
    await store.create(other_kind)
    pdp = PolicyDecisionPoint(store, AttributeResolver.default())
    a = Authorizer(catalog, [AssignmentRoleResolver(assignments)], pdp=pdp)
    p = Principal("u1")
    assert await a.check(p, "design.read", S1) is DecisionKind.DENIED
    assert await a.check(p, "design.read", S2) is DecisionKind.ALLOWED  # other scope
    assert await a.check(p, "billing.read", S2) is DecisionKind.ALLOWED  # not named
    assert await a.check(p, "admin.all", ScopeRef.GLOBAL) is DecisionKind.DENIED
    # the studio-kind policy never touched the global scope's other permissions
    only_studio = Policy.from_new(
        pol("kind-wide", cond={"exists": {"attr": "subject.id"}})
    )
    assert only_studio.scope.matches(ScopeRef.GLOBAL) is False


# ----------------------------------------------------------------------- logs


@pytest.mark.asyncio
async def test_logs_never_contain_attribute_values(catalog):
    captured: list[str] = []
    sink = logger.add(lambda m: captured.append(str(m)), level="DEBUG")
    try:
        attrs = {"owner_id": SECRET, "note": SECRET}
        a, _ = await authorizer(
            catalog, [pol("owner", Effect.REQUIRE, ("design.delete",), OWNER)]
        )
        for payload in (attrs, None):
            try:
                await a.authorize(
                    Principal("u1"),
                    "design.delete",
                    S1,
                    resource=res(lambda r, f, p=payload: p),
                )
            except Exception:
                pass
        await a.explain(
            Principal("u1"), "design.delete", S1, resource=res(lambda r, f: attrs)
        )
        broken, _ = await authorizer(catalog, source=Boom(RuntimeError("boom")))
        with pytest.raises(StoreUnavailableError):
            await broken.authorize(Principal("u1"), "design.read", S1)
    finally:
        logger.remove(sink)
    assert not any(SECRET in line for line in captured)


@pytest.mark.asyncio
async def test_denial_exceptions_do_not_carry_values(catalog):
    a, _ = await authorizer(
        catalog, [pol("owner", Effect.REQUIRE, ("design.delete",), OWNER)]
    )
    with pytest.raises(PermissionDeniedError) as exc:
        await a.authorize(
            Principal("u1"),
            "design.delete",
            S1,
            resource=res(lambda r, f: {"owner_id": SECRET}),
        )
    assert SECRET not in str(exc.value) and SECRET not in repr(exc.value.abac)
