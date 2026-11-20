"""AUTHZ-033 (cache) and the static/composite sources of AUTHZ-032."""

from __future__ import annotations

import asyncio
import json

import pytest

from auth_middleware.authz import ConfigurationError, ScopeRef, StoreUnavailableError
from auth_middleware.authz.abac.cache import CachingPolicySource
from auth_middleware.authz.abac.service import PolicyChange
from auth_middleware.authz.abac.sources import CompositePolicySource, StaticPolicySource
from auth_middleware.authz.abac.types import (
    Effect,
    NewPolicy,
    Policy,
    PolicyScope,
    PolicyStatus,
)
from auth_middleware.authz.errors import InvalidPolicyError
from auth_middleware.authz.stores.memory import InMemoryPolicyStore

S1, S2 = ScopeRef("studio", "s1"), ScopeRef("studio", "s2")
COND = {"eq": [{"attr": "subject.id"}, "x"]}


def np(pid, scope=None, **kw):
    return NewPolicy(
        pid, Effect.DENY, ("design.*",), scope or PolicyScope("studio"), COND, **kw
    )


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class CountingStore(InMemoryPolicyStore):
    def __init__(self):
        super().__init__()
        self.calls = 0
        self.fail = False
        self.gate: asyncio.Event | None = None

    async def list_policies(self, scope):
        self.calls += 1
        if self.gate is not None:
            await self.gate.wait()
        if self.fail:
            raise StoreUnavailableError("down")
        return await super().list_policies(scope)


@pytest.mark.asyncio
async def test_hit_expiry_and_eviction():
    clock, inner = Clock(), CountingStore()
    await inner.create(np("a"))
    cache = CachingPolicySource(inner, ttl_seconds=5, max_scopes=2, clock=clock)
    assert [p.id for p in await cache.list_policies(S1)] == ["a"]
    await cache.list_policies(S1)
    assert inner.calls == 1
    clock.now += 5.1
    await cache.list_policies(S1)
    assert inner.calls == 2
    await cache.list_policies(S2)
    await cache.list_policies(ScopeRef("studio", "s3"))  # evicts the oldest (s1)
    calls = inner.calls
    await cache.list_policies(S1)
    assert inner.calls == calls + 1


@pytest.mark.asyncio
async def test_invalidate_and_on_change():
    inner = CountingStore()
    await inner.create(np("a"))
    cache = CachingPolicySource(inner, ttl_seconds=5)
    await cache.list_policies(S1)
    await cache.list_policies(S2)
    cache.invalidate(S1)
    await cache.list_policies(S1)
    await cache.list_policies(S2)
    assert inner.calls == 3
    created = await inner.create(np("b", PolicyScope("studio", "s1")))
    cache.on_change(PolicyChange("create", created))  # scope policy: only s1
    await cache.list_policies(S2)
    assert inner.calls == 3
    assert {p.id for p in await cache.list_policies(S1)} == {"a", "b"}
    wide = await inner.create(np("c"))
    cache.on_change(PolicyChange("create", wide))  # kind-wide: every studio
    await cache.list_policies(S2)
    assert inner.calls == 5
    cache.invalidate()
    await cache.list_policies(S2)
    assert inner.calls == 6


@pytest.mark.asyncio
async def test_single_flight_on_a_cold_key():
    inner = CountingStore()
    inner.gate = asyncio.Event()
    await inner.create(np("a"))
    cache = CachingPolicySource(inner, ttl_seconds=5)
    tasks = [asyncio.create_task(cache.list_policies(S1)) for _ in range(100)]
    await asyncio.sleep(0)
    inner.gate.set()
    results = await asyncio.gather(*tasks)
    assert inner.calls == 1 and all(len(r) == 1 for r in results)


@pytest.mark.asyncio
async def test_invalidate_during_a_load_wins():
    inner = CountingStore()
    inner.gate = asyncio.Event()
    await inner.create(np("a"))
    cache = CachingPolicySource(inner, ttl_seconds=5)
    task = asyncio.create_task(cache.list_policies(S1))
    await asyncio.sleep(0)
    cache.invalidate(S1)  # a write happened while the old snapshot was loading
    inner.gate.set()
    await task
    inner.gate = None
    await cache.list_policies(S1)
    assert inner.calls == 2  # the stale result was not stored


@pytest.mark.asyncio
async def test_failure_is_not_cached_and_stale_is_never_served():
    clock, inner = Clock(), CountingStore()
    await inner.create(np("a"))
    cache = CachingPolicySource(inner, ttl_seconds=5, clock=clock)
    inner.fail = True
    with pytest.raises(StoreUnavailableError):
        await cache.list_policies(S1)
    inner.fail = False
    await cache.list_policies(S1)
    clock.now += 6
    inner.fail = True
    with pytest.raises(StoreUnavailableError):  # warm entry past TTL: no stale serving
        await cache.list_policies(S1)


def test_ttl_rules_and_passthrough():
    inner = InMemoryPolicyStore()
    for bad in (0, -1):
        with pytest.raises(ConfigurationError):
            CachingPolicySource(inner, ttl_seconds=bad)
    with pytest.raises(ConfigurationError):
        CachingPolicySource(inner, ttl_seconds=61)
    CachingPolicySource(inner, ttl_seconds=61, i_understand_stale_authorization=True)
    with pytest.raises(ConfigurationError):
        CachingPolicySource(inner, ttl_seconds=5, max_scopes=0)


@pytest.mark.asyncio
async def test_list_all_is_not_cached_and_aclose_reaches_the_inner_source():
    closed = []

    class Closable(InMemoryPolicyStore):
        async def aclose(self):
            closed.append(1)

    inner = Closable()
    await inner.create(np("a"))
    cache = CachingPolicySource(inner, ttl_seconds=5)
    assert len(await cache.list_all()) == 1
    await cache.aclose()
    assert closed == [1]


@pytest.mark.asyncio
async def test_concurrent_decisions_do_not_corrupt_the_cache():
    inner = CountingStore()
    await inner.create(np("a"))
    cache = CachingPolicySource(inner, ttl_seconds=5, max_scopes=10)

    async def hit(i):
        return await cache.list_policies(ScopeRef("studio", f"s{i % 25}"))

    results = await asyncio.gather(*(hit(i) for i in range(500)))
    assert all([p.id for p in r] == ["a"] for r in results)


# ----------------------------------------------------------------- sources


def doc(pid="static-1", **kw):
    base = {
        "id": pid,
        "effect": "deny",
        "permissions": ["design.*"],
        "scope": {"kind": "studio"},
        "condition": COND,
    }
    base.update(kw)
    return base


@pytest.mark.asyncio
async def test_static_source_from_code_json_and_toml(tmp_path):
    src = StaticPolicySource([doc(), np("b"), Policy.from_new(np("c"))])
    assert [p.id for p in await src.list_policies(S1)] == ["b", "c", "static-1"]
    assert await src.list_all(PolicyStatus.DISABLED) == []
    j = tmp_path / "p.json"
    j.write_text(json.dumps({"policies": [doc("from-json", status="disabled")]}))
    from_json = StaticPolicySource.from_file(j)
    assert await from_json.list_policies(S1) == []
    assert len(await from_json.list_all(PolicyStatus.DISABLED)) == 1
    t = tmp_path / "p.toml"
    t.write_text(
        '[[policies]]\nid = "from-toml"\neffect = "require"\npermissions = ["design.read"]\n'
        'scope = {kind = "studio", id = "s1"}\n'
        'condition = {eq = [{attr = "subject.id"}, "x"]}\n'
    )
    from_toml = StaticPolicySource.from_file(t)
    assert [p.id for p in await from_toml.list_policies(S1)] == ["from-toml"]
    assert await from_toml.list_policies(S2) == []


def test_static_source_errors(tmp_path):
    with pytest.raises(InvalidPolicyError, match="duplicate"):
        StaticPolicySource([doc(), doc()])
    with pytest.raises(InvalidPolicyError):
        StaticPolicySource([doc(effect="maybe")])
    bad = tmp_path / "p.yaml"
    bad.write_text("x")
    with pytest.raises(InvalidPolicyError, match="unsupported"):
        StaticPolicySource.from_file(bad)
    with pytest.raises(InvalidPolicyError):
        StaticPolicySource.from_file(tmp_path / "missing.json")
    nolist = tmp_path / "n.json"
    nolist.write_text('{"policies": 5}')
    with pytest.raises(InvalidPolicyError):
        StaticPolicySource.from_file(nolist)
    garbage = tmp_path / "g.json"
    garbage.write_text("{nope")
    with pytest.raises(InvalidPolicyError):
        StaticPolicySource.from_file(garbage)


@pytest.mark.asyncio
async def test_composite_first_wins_and_verify():
    a = StaticPolicySource([doc("same", description="from a")])
    b = StaticPolicySource([doc("same", description="from b"), doc("only-b")])
    both = CompositePolicySource(a, b)
    got = {p.id: p.description for p in await both.list_policies(S1)}
    assert got == {"same": "from a", "only-b": ""}
    assert len(await both.list_all()) == 3
    with pytest.raises(ConfigurationError, match="same"):
        await both.verify()
    await CompositePolicySource(a, StaticPolicySource([doc("other")])).verify()
    with pytest.raises(ConfigurationError):
        CompositePolicySource()
