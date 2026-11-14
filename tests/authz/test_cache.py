from __future__ import annotations

import asyncio

import pytest

from auth_middleware.authz import (
    Authz,
    CachingAssignmentStore,
    ConfigurationError,
    NewAssignment,
    ScopeRef,
)
from auth_middleware.authz.stores import InMemoryAssignmentStore

S = ScopeRef("studio", "s1")


class Counting(InMemoryAssignmentStore):
    def __init__(self):
        super().__init__()
        self.reads = 0

    async def get_assignment(self, principal_id, scope):
        self.reads += 1
        return await super().get_assignment(principal_id, scope)


class Clock:
    now = 0.0

    def __call__(self):
        return self.now


@pytest.mark.asyncio
async def test_hit_miss_and_negative_expires_sooner():
    inner, clock = Counting(), Clock()
    cache = CachingAssignmentStore(inner, ttl_seconds=40, clock=clock)
    await inner.assign(NewAssignment("u", S, "R"))
    await cache.get_assignment("u", S)
    await cache.get_assignment("u", S)
    assert inner.reads == 1
    clock.now = 41
    await cache.get_assignment("u", S)
    assert inner.reads == 2
    # negative entry: ttl/4 = 10 s
    await cache.get_assignment("nobody", S)
    clock.now = 41 + 9
    await cache.get_assignment("nobody", S)
    assert inner.reads == 3
    clock.now = 41 + 11
    await cache.get_assignment("nobody", S)
    assert inner.reads == 4


@pytest.mark.asyncio
async def test_invalidate_and_write_through():
    inner = Counting()
    cache = CachingAssignmentStore(inner, ttl_seconds=30, clock=Clock())
    first = await cache.assign(NewAssignment("u", S, "R"))
    assert (await cache.get_assignment("u", S)).role == "R"
    await cache.change_role("u", S, "X", expected_revision=first.revision)
    assert (await cache.get_assignment("u", S)).role == "X"
    await cache.revoke("u", S, expected_revision=1)
    assert (await cache.get_assignment("u", S)).status.value == "revoked"
    # a write made behind the cache's back stays hidden until invalidated
    await inner.assign(NewAssignment("v", S, "R"))
    assert await cache.get_assignment("v", S) is not None
    inner._items.clear()
    assert await cache.get_assignment("v", S) is not None
    cache.invalidate("v")
    assert await cache.get_assignment("v", S) is None
    assert [a.principal_id for a in await cache.list_for_scope(S)] == []


@pytest.mark.asyncio
async def test_max_entries_evicts_oldest():
    inner = Counting()
    cache = CachingAssignmentStore(inner, ttl_seconds=30, max_entries=2, clock=Clock())
    for p in ("a", "b", "c"):
        await cache.get_assignment(p, S)
    assert inner.reads == 3
    await cache.get_assignment("c", S)
    await cache.get_assignment("b", S)
    assert inner.reads == 3
    await cache.get_assignment("a", S)  # evicted
    assert inner.reads == 4


def test_ttl_cap_and_flag():
    inner = InMemoryAssignmentStore()
    with pytest.raises(ConfigurationError):
        CachingAssignmentStore(inner, ttl_seconds=61)
    with pytest.raises(ConfigurationError):
        CachingAssignmentStore(inner, ttl_seconds=0)
    CachingAssignmentStore(
        inner, ttl_seconds=300, i_understand_stale_authorization=True
    )


@pytest.mark.asyncio
async def test_concurrent_tasks_do_not_corrupt():
    inner = Counting()
    cache = CachingAssignmentStore(inner, ttl_seconds=30, max_entries=10, clock=Clock())
    await inner.assign(NewAssignment("u0", S, "R"))
    results = await asyncio.gather(
        *(cache.get_assignment(f"u{i % 20}", S) for i in range(100))
    )
    assert len(cache._entries) <= 10
    assert all((r is None) == (i % 20 != 0) for i, r in enumerate(results))


def test_authz_build_never_wraps_the_store(catalog):
    store = InMemoryAssignmentStore()
    authz = Authz.build(catalog=catalog, store=store)
    assert authz._store is store
    assert not isinstance(authz._store, CachingAssignmentStore)


@pytest.mark.asyncio
async def test_admin_methods_require_an_admin_inner_store():
    class ReadOnly:
        async def get_assignment(self, p, s):
            return None

        async def list_assignments(self, p):
            return []

    cache = CachingAssignmentStore(ReadOnly(), ttl_seconds=5)
    with pytest.raises(ConfigurationError):
        await cache.assign(NewAssignment("u", S, "R"))
    await cache.aclose()
