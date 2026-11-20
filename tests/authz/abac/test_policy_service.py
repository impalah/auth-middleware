"""AUTHZ-032: PolicyService."""

from __future__ import annotations

import asyncio

import pytest

from auth_middleware.authz import RevisionConflictError, ScopeRef
from auth_middleware.authz.abac.cache import CachingPolicySource
from auth_middleware.authz.abac.service import PolicyChange, PolicyService
from auth_middleware.authz.abac.types import (
    Effect,
    NewPolicy,
    PolicyScope,
    PolicyStatus,
)
from auth_middleware.authz.errors import InvalidPolicyError, PolicyConflictError
from auth_middleware.authz.stores.memory import InMemoryPolicyStore

OK = {"eq": [{"attr": "subject.attrs.clearance"}, 3]}


def np(pid="p1", cond=None, **kw):
    return NewPolicy(
        pid,
        kw.pop("effect", Effect.DENY),
        ("design.write",),
        PolicyScope("studio"),
        cond or OK,
        **kw,
    )


class Spy(InMemoryPolicyStore):
    def __init__(self):
        super().__init__()
        self.writes = 0

    async def create(self, new):
        self.writes += 1
        return await super().create(new)

    async def replace(self, *a, **kw):
        self.writes += 1
        return await super().replace(*a, **kw)


@pytest.mark.asyncio
async def test_invalid_policies_never_reach_the_store(catalog):
    store = Spy()
    service = PolicyService(store, catalog)
    for bad in (
        np(cond={"eq": [{"attr": "subject.attrs.ghost"}, 1]}),
        np(effect=Effect.PERMIT),
        NewPolicy("p2", Effect.DENY, ("nope.*",), PolicyScope("studio"), OK),
    ):
        with pytest.raises(InvalidPolicyError):
            await service.create(bad)
    with pytest.raises(InvalidPolicyError):
        await service.replace("p1", np("other"), expected_revision=0)
    assert store.writes == 0


@pytest.mark.asyncio
async def test_lifecycle_and_hooks(catalog):
    store = InMemoryPolicyStore()
    seen: list[PolicyChange] = []

    async def async_hook(change):
        seen.append(change)

    cache = CachingPolicySource(store, ttl_seconds=5)
    service = PolicyService(
        store, catalog, allow_permit=True, after_change=[async_hook, cache.on_change]
    )
    await cache.list_policies(ScopeRef("studio", "s1"))
    created = await service.create(np())
    assert [p.id for p in await cache.list_policies(ScopeRef("studio", "s1"))] == ["p1"]
    replaced = await service.replace("p1", np(description="v2"), expected_revision=0)
    off = await service.disable("p1", expected_revision=replaced.revision)
    on = await service.enable("p1", expected_revision=off.revision)
    assert on.status is PolicyStatus.ACTIVE and on.revision == 3
    assert [c.kind for c in seen] == ["create", "replace", "disable", "enable"]
    assert (await service.get("p1")).description == "v2"
    assert created.revision == 0
    with pytest.raises(PolicyConflictError):
        await service.create(np())
    permit = await service.create(np("g", effect=Effect.PERMIT))
    assert permit.effect is Effect.PERMIT


@pytest.mark.asyncio
async def test_concurrent_replace_one_winner(catalog):
    service = PolicyService(InMemoryPolicyStore(), catalog)
    await service.create(np())

    async def attempt(i):
        try:
            await service.replace("p1", np(description=f"d{i}"), expected_revision=0)
        except RevisionConflictError:
            return False
        return True

    assert (await asyncio.gather(*(attempt(i) for i in range(10)))).count(True) == 1


@pytest.mark.asyncio
async def test_failing_hooks_all_run_and_first_error_is_raised(catalog):
    ran = []

    def boom(change):
        ran.append("boom")
        raise RuntimeError("first")

    def later(change):
        ran.append("later")

    service = PolicyService(InMemoryPolicyStore(), catalog, after_change=[boom, later])
    with pytest.raises(RuntimeError, match="first"):
        await service.create(np())
    assert ran == ["boom", "later"]  # the write is done, every hook ran
