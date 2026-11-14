"""Reusable store contract suite.

Subclass :class:`AssignmentStoreContract`, implement ``make_store`` and run
with pytest-asyncio (every ``test_*`` is a plain ``async def``; decorate the
subclass with ``@pytest.mark.asyncio`` or use ``asyncio_mode = auto``).
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from contextlib import AbstractAsyncContextManager
from datetime import timedelta
from typing import Any, Protocol

from auth_middleware.authz.errors import RevisionConflictError
from auth_middleware.authz.ports import AssignmentAdmin, AssignmentStore
from auth_middleware.authz.types import (
    Assignment,
    AssignmentStatus,
    NewAssignment,
    ScopeRef,
)


class FullStore(AssignmentStore, AssignmentAdmin, Protocol):
    """A store implementing both ports."""


class AssignmentStoreContract(ABC):
    """Behaviour every backend must have. Case names are stable."""

    #: Set to ``False`` in backends that do not persist ``attributes``.
    supports_attributes: bool = True

    @abstractmethod
    def make_store(self) -> AbstractAsyncContextManager[Any]:
        """Async context manager yielding a fresh, empty ``FullStore``."""

    @staticmethod
    def _new(
        principal: str = "u1",
        scope: ScopeRef | None = None,
        role: str = "EDI",
        **attrs: Any,
    ) -> NewAssignment:
        return NewAssignment(principal, scope or ScopeRef("studio", "s1"), role, attrs)

    async def test_get_unknown_returns_none(self) -> None:
        async with self.make_store() as store:
            assert await store.get_assignment("nobody", ScopeRef("studio", "x")) is None

    async def test_assign_then_get(self) -> None:
        async with self.make_store() as store:
            new = self._new()
            await store.assign(new)
            got = await store.get_assignment(new.principal_id, new.scope)
            assert got is not None
            assert got.role == "EDI"
            assert got.status is AssignmentStatus.ACTIVE
            assert got.revision == 0
            assert got.created_at is not None
            assert got.created_at.utcoffset() == timedelta(0)

    async def test_assign_twice_conflicts(self) -> None:
        async with self.make_store() as store:
            await store.assign(self._new())
            try:
                await store.assign(self._new())
            except RevisionConflictError:
                return
            raise AssertionError("expected RevisionConflictError")

    async def test_change_role_bumps_revision_and_rejects_stale(self) -> None:
        async with self.make_store() as store:
            new = self._new()
            first = await store.assign(new)
            changed = await store.change_role(
                new.principal_id, new.scope, "LEC", expected_revision=first.revision
            )
            assert changed.role == "LEC"
            assert changed.revision == first.revision + 1
            got = await store.get_assignment(new.principal_id, new.scope)
            assert got is not None and got.role == "LEC"
            try:
                await store.change_role(
                    new.principal_id,
                    new.scope,
                    "TIT",
                    expected_revision=first.revision,
                )
            except RevisionConflictError:
                return
            raise AssertionError("expected RevisionConflictError")

    async def test_revoke(self) -> None:
        async with self.make_store() as store:
            new = self._new()
            first = await store.assign(new)
            revoked = await store.revoke(
                new.principal_id, new.scope, expected_revision=first.revision
            )
            assert revoked.status is AssignmentStatus.REVOKED
            assert revoked.revision == first.revision + 1
            got = await store.get_assignment(new.principal_id, new.scope)
            assert got is None or got.status is AssignmentStatus.REVOKED

    async def test_assign_after_revoke_reactivates(self) -> None:
        async with self.make_store() as store:
            new = self._new()
            first = await store.assign(new)
            revoked = await store.revoke(
                new.principal_id, new.scope, expected_revision=first.revision
            )
            again = await store.assign(self._new(role="TIT"))
            assert again.status is AssignmentStatus.ACTIVE
            assert again.role == "TIT"
            assert again.revision == revoked.revision + 1
            got = await store.get_assignment(new.principal_id, new.scope)
            assert got is not None
            assert got.role == "TIT" and got.status is AssignmentStatus.ACTIVE

    async def test_list_assignments_is_per_principal(self) -> None:
        async with self.make_store() as store:
            await store.assign(self._new("u1", ScopeRef("studio", "a")))
            await store.assign(self._new("u1", ScopeRef("studio", "b")))
            await store.assign(self._new("u2", ScopeRef("studio", "a")))
            got = await store.list_assignments("u1")
            assert {(a.principal_id, a.scope.id) for a in got} == {
                ("u1", "a"),
                ("u1", "b"),
            }

    async def test_list_for_scope_is_per_scope(self) -> None:
        async with self.make_store() as store:
            await store.assign(self._new("u1", ScopeRef("studio", "a")))
            await store.assign(self._new("u2", ScopeRef("studio", "a")))
            await store.assign(self._new("u3", ScopeRef("studio", "b")))
            got = await store.list_for_scope(ScopeRef("studio", "a"))
            assert {a.principal_id for a in got} == {"u1", "u2"}

    async def test_scope_isolation(self) -> None:
        async with self.make_store() as store:
            a, b = ScopeRef("studio", "a"), ScopeRef("studio", "b")
            fa = await store.assign(self._new("u1", a, "EDI"))
            await store.assign(self._new("u1", b, "LEC"))
            await store.change_role("u1", a, "TIT", expected_revision=fa.revision)
            got_b = await store.get_assignment("u1", b)
            assert got_b is not None
            assert got_b.role == "LEC" and got_b.revision == 0

    async def test_attributes_round_trip(self) -> None:
        if not self.supports_attributes:
            from unittest import SkipTest  # pytest treats it as a skip

            raise SkipTest("backend does not store attributes")
        async with self.make_store() as store:
            new = self._new(status="suspended")
            await store.assign(new)
            got = await store.get_assignment(new.principal_id, new.scope)
            assert got is not None
            assert dict(got.attributes) == {"status": "suspended"}

    async def test_concurrent_assign_has_one_winner(self) -> None:
        async with self.make_store() as store:
            results = await asyncio.gather(
                *(store.assign(self._new()) for _ in range(20)),
                return_exceptions=True,
            )
            winners = [r for r in results if isinstance(r, Assignment)]
            losers = [r for r in results if isinstance(r, RevisionConflictError)]
            assert len(winners) == 1
            assert len(losers) == 19

    async def test_ids_are_case_and_accent_sensitive(self) -> None:
        async with self.make_store() as store:
            scope = ScopeRef("studio", "Studio")
            await store.assign(self._new("Abc", scope, "EDI"))
            await store.assign(self._new("abc", scope, "LEC"))
            await store.assign(self._new("abç", scope, "TIT"))
            assert await store.get_assignment("ABC", scope) is None
            assert await store.get_assignment("studio", scope) is None
            lower = await store.get_assignment("abc", scope)
            assert lower is not None and lower.role == "LEC"
            assert (
                await store.get_assignment("abc", ScopeRef("studio", "studio")) is None
            )
            assert len(await store.list_for_scope(scope)) == 3

    async def test_unicode_and_long_ids(self) -> None:
        async with self.make_store() as store:
            scope = ScopeRef("studio", "é" * 100 + "日本" * 50)
            principal = "ü" * 200
            await store.assign(self._new(principal, scope))
            got = await store.get_assignment(principal, scope)
            assert got is not None
            assert got.principal_id == principal and got.scope == scope
