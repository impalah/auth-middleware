"""Reusable contract suite for the ABAC stores (policies and attributes).

Same usage as :mod:`auth_middleware.authz.testing.contract`: subclass, implement
``make_store`` (an async context manager yielding a fresh, empty store) and run
with pytest-asyncio.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from contextlib import AbstractAsyncContextManager
from typing import Any

from auth_middleware.authz.abac.types import (
    Effect,
    EntityRef,
    NewPolicy,
    PolicyScope,
    PolicyStatus,
)
from auth_middleware.authz.errors import (
    InvalidPolicyError,
    PolicyConflictError,
    RevisionConflictError,
    StoreUnavailableError,
)
from auth_middleware.authz.types import ScopeRef

COND = {"eq": [{"attr": "subject.id"}, "x"]}


def _expect(exc: type[Exception]) -> Any:
    class _Expect:
        def __enter__(self) -> None:
            return None

        def __exit__(self, kind: Any, value: Any, tb: Any) -> bool:
            if kind is None:
                raise AssertionError(f"expected {exc.__name__}")
            return issubclass(kind, exc)

    return _Expect()


class PolicyStoreContract(ABC):
    """Behaviour every policy store must have. Case names are stable."""

    @abstractmethod
    def make_store(self) -> AbstractAsyncContextManager[Any]:
        """Async context manager yielding a fresh store (policies port + admin)."""

    def make_failing_store(self) -> AbstractAsyncContextManager[Any] | None:
        """Optional: a store whose backend is down (enables the outage case)."""
        return None

    @staticmethod
    def _new(
        policy_id: str = "p1",
        scope: PolicyScope | None = None,
        **kw: Any,
    ) -> NewPolicy:
        base: dict[str, Any] = {
            "id": policy_id,
            "effect": Effect.DENY,
            "permissions": ("design.write", "*.delete"),
            "scope": scope or PolicyScope("studio", "s1"),
            "condition": COND,
            "description": "d",
            "priority": 2,
            "hide": True,
            "enforce": False,
        }
        base.update(kw)
        return NewPolicy(**base)

    async def test_create_get_round_trip(self) -> None:
        async with self.make_store() as store:
            new = self._new()
            created = await store.create(new)
            assert created.revision == 0 and created.status is PolicyStatus.ACTIVE
            assert created.created_at is not None and created.updated_at is not None
            got = await store.get("p1")
            assert got is not None and got.to_new() == new
            assert got.condition == COND and got.permissions == new.permissions
            assert got.hide is True and got.enforce is False and got.priority == 2

    async def test_get_unknown_is_none(self) -> None:
        async with self.make_store() as store:
            assert await store.get("nope") is None

    async def test_duplicate_id_conflicts(self) -> None:
        async with self.make_store() as store:
            await store.create(self._new())
            with _expect(PolicyConflictError):
                await store.create(self._new())
            with _expect(PolicyConflictError):  # ids are unique across scopes
                await store.create(self._new(scope=PolicyScope("company")))

    async def test_list_policies_selects_scope_and_kind_wide(self) -> None:
        async with self.make_store() as store:
            await store.create(self._new("b-scope", priority=1))
            await store.create(self._new("a-scope", priority=1))
            await store.create(
                self._new("kind", scope=PolicyScope("studio"), priority=0)
            )
            await store.create(
                self._new("other-scope", scope=PolicyScope("studio", "s2"))
            )
            await store.create(self._new("other-kind", scope=PolicyScope("company")))
            await store.create(self._new("off"))
            off = await store.get("off")
            await store.set_status(
                "off", PolicyStatus.DISABLED, expected_revision=off.revision
            )
            got = await store.list_policies(ScopeRef("studio", "s1"))
            assert [p.id for p in got] == ["kind", "a-scope", "b-scope"]
            assert [
                p.id for p in await store.list_policies(ScopeRef("studio", "zz"))
            ] == ["kind"]
            assert await store.list_policies(ScopeRef("nothing", "x")) == []

    async def test_global_scope(self) -> None:
        async with self.make_store() as store:
            await store.create(self._new("g", scope=PolicyScope("global")))
            got = await store.list_policies(ScopeRef.GLOBAL)
            assert [p.id for p in got] == ["g"]

    async def test_replace_checks_revision_and_bumps(self) -> None:
        async with self.make_store() as store:
            await store.create(self._new())
            changed = await store.replace(
                "p1",
                self._new(description="new", hide=False),
                expected_revision=0,
            )
            assert changed.revision == 1 and changed.description == "new"
            got = await store.get("p1")
            assert got is not None and got.hide is False and got.revision == 1
            with _expect(RevisionConflictError):
                await store.replace("p1", self._new(), expected_revision=0)

    async def test_scope_and_id_are_immutable(self) -> None:
        async with self.make_store() as store:
            await store.create(self._new())
            with _expect(InvalidPolicyError):
                await store.replace(
                    "p1",
                    self._new(scope=PolicyScope("studio", "s9")),
                    expected_revision=0,
                )
            with _expect(InvalidPolicyError):
                await store.replace("p1", self._new("p2"), expected_revision=0)

    async def test_set_status_hides_from_list_but_not_from_get(self) -> None:
        async with self.make_store() as store:
            await store.create(self._new())
            off = await store.set_status(
                "p1", PolicyStatus.DISABLED, expected_revision=0
            )
            assert off.revision == 1 and off.status is PolicyStatus.DISABLED
            assert await store.list_policies(ScopeRef("studio", "s1")) == []
            assert (await store.get("p1")) is not None
            assert [p.id for p in await store.list_all()] == ["p1"]
            assert await store.list_all(PolicyStatus.ACTIVE) == []
            assert len(await store.list_all(PolicyStatus.DISABLED)) == 1
            on = await store.set_status("p1", PolicyStatus.ACTIVE, expected_revision=1)
            assert on.revision == 2
            assert len(await store.list_policies(ScopeRef("studio", "s1"))) == 1
            with _expect(RevisionConflictError):
                await store.set_status("p1", PolicyStatus.DISABLED, expected_revision=1)

    async def test_unknown_id_looks_like_a_stale_revision(self) -> None:
        async with self.make_store() as store:
            with _expect(RevisionConflictError):
                await store.replace("ghost", self._new("ghost"), expected_revision=0)
            with _expect(RevisionConflictError):
                await store.set_status(
                    "ghost", PolicyStatus.DISABLED, expected_revision=0
                )

    async def test_concurrent_replace_has_exactly_one_winner(self) -> None:
        async with self.make_store() as store:
            await store.create(self._new())

            async def attempt(i: int) -> bool:
                try:
                    await store.replace(
                        "p1", self._new(description=f"d{i}"), expected_revision=0
                    )
                except RevisionConflictError:
                    return False
                return True

            results = await asyncio.gather(*(attempt(i) for i in range(20)))
            assert results.count(True) == 1
            got = await store.get("p1")
            assert got is not None and got.revision == 1

    async def test_concurrent_create_has_exactly_one_winner(self) -> None:
        async with self.make_store() as store:

            async def attempt(i: int) -> bool:
                try:
                    await store.create(self._new(scope=PolicyScope("studio", f"s{i}")))
                except PolicyConflictError:
                    return False
                return True

            results = await asyncio.gather(*(attempt(i) for i in range(10)))
            assert results.count(True) == 1

    async def test_oversized_policy_is_rejected_before_any_store(self) -> None:
        with _expect(InvalidPolicyError):
            self._new(condition={"eq": ["x" * 20_000, 1]})

    async def test_ids_are_exact(self) -> None:
        async with self.make_store() as store:
            await store.create(self._new("abc", scope=PolicyScope("studio", "Abc")))
            await store.create(self._new("abd", scope=PolicyScope("studio", "abc")))
            assert await store.get("ABC") is None
            upper = await store.list_policies(ScopeRef("studio", "Abc"))
            lower = await store.list_policies(ScopeRef("studio", "abc"))
            assert [p.id for p in upper] == ["abc"]
            assert [p.id for p in lower] == ["abd"]

    async def test_outage_is_store_unavailable(self) -> None:
        ctx = self.make_failing_store()
        if ctx is None:
            return
        async with ctx as store:
            with _expect(StoreUnavailableError):
                await store.list_policies(ScopeRef("studio", "s1"))
            with _expect(StoreUnavailableError):
                await store.create(self._new())


class AttributeStoreContract(ABC):
    """Behaviour every attribute store must have."""

    @abstractmethod
    def make_store(self) -> AbstractAsyncContextManager[Any]:
        """Async context manager yielding a fresh, empty attribute store."""

    def make_failing_store(self) -> AbstractAsyncContextManager[Any] | None:
        """Optional: a store whose backend is down."""
        return None

    async def test_get_unknown_is_none(self) -> None:
        async with self.make_store() as store:
            assert await store.get_attributes(EntityRef.principal("nobody")) is None

    async def test_put_get_update_delete(self) -> None:
        async with self.make_store() as store:
            ref = EntityRef.principal("u1")
            first = await store.put_attributes(
                ref,
                {"dept": "x", "n": 1, "t": ["a"], "m": {"k": True}},
                expected_revision=None,
            )
            assert first.revision == 0
            got = await store.get_attributes(ref)
            assert got is not None
            assert dict(got.attributes) == {
                "dept": "x",
                "n": 1,
                "t": ["a"],
                "m": {"k": True},
            }
            second = await store.put_attributes(ref, {"dept": "y"}, expected_revision=0)
            assert second.revision == 1 and dict(second.attributes) == {"dept": "y"}
            with _expect(RevisionConflictError):
                await store.put_attributes(ref, {"dept": "z"}, expected_revision=0)
            with _expect(RevisionConflictError):
                await store.delete_attributes(ref, expected_revision=0)
            await store.delete_attributes(ref, expected_revision=1)
            assert await store.get_attributes(ref) is None

    async def test_create_twice_and_unknown_update_conflict(self) -> None:
        async with self.make_store() as store:
            ref = EntityRef.principal("u1")
            await store.put_attributes(ref, {}, expected_revision=None)
            with _expect(RevisionConflictError):
                await store.put_attributes(ref, {}, expected_revision=None)
            with _expect(RevisionConflictError):
                await store.put_attributes(
                    EntityRef.principal("ghost"), {}, expected_revision=0
                )
            with _expect(RevisionConflictError):
                await store.delete_attributes(
                    EntityRef.principal("ghost"), expected_revision=0
                )

    async def test_namespaces_do_not_collide(self) -> None:
        async with self.make_store() as store:
            person = EntityRef.principal("same")
            thing = EntityRef("resource", "design", "same")
            other_kind = EntityRef("resource", "folder", "same")
            await store.put_attributes(person, {"a": 1}, expected_revision=None)
            await store.put_attributes(thing, {"a": 2}, expected_revision=None)
            await store.put_attributes(other_kind, {"a": 3}, expected_revision=None)
            for ref, value in ((person, 1), (thing, 2), (other_kind, 3)):
                got = await store.get_attributes(ref)
                assert got is not None and got.attributes["a"] == value

    async def test_size_and_shape_limits(self) -> None:
        async with self.make_store() as store:
            ref = EntityRef.principal("u1")
            for bad in (
                {"a": "x" * 5000},
                {"a": list(range(101))},
                {"a": {"b": {"c": {"d": 1}}}},
                {"bad key": 1},
                {"a": object()},
            ):
                with _expect(InvalidPolicyError):
                    await store.put_attributes(ref, bad, expected_revision=None)
            assert await store.get_attributes(ref) is None

    async def test_keys_and_ids_are_case_sensitive(self) -> None:
        async with self.make_store() as store:
            upper, lower = EntityRef.principal("Abc"), EntityRef.principal("abc")
            await store.put_attributes(upper, {"K": 1, "k": 2}, expected_revision=None)
            await store.put_attributes(lower, {"x": 3}, expected_revision=None)
            got = await store.get_attributes(upper)
            assert got is not None and dict(got.attributes) == {"K": 1, "k": 2}
            other = await store.get_attributes(lower)
            assert other is not None and dict(other.attributes) == {"x": 3}

    async def test_outage_is_store_unavailable(self) -> None:
        ctx = self.make_failing_store()
        if ctx is None:
            return
        async with ctx as store:
            with _expect(StoreUnavailableError):
                await store.get_attributes(EntityRef.principal("u1"))
