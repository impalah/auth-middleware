"""Assignment service: where an application enforces its rules around who holds what."""

from __future__ import annotations

import asyncio
import weakref
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from loguru import logger

from auth_middleware.authz.catalog import PermissionCatalog
from auth_middleware.authz.errors import ScopeKindMismatchError, UnknownRoleError
from auth_middleware.authz.ports import AssignmentAdmin, AssignmentStore
from auth_middleware.authz.types import Assignment, NewAssignment, ScopeRef


@dataclass(frozen=True, slots=True)
class AssignmentChange:
    """A change about to happen (or that happened) to an assignment."""

    kind: Literal["assign", "change_role", "revoke"]
    principal_id: str
    scope: ScopeRef
    old: Assignment | None
    new_role: str | None


BeforeChange = Callable[[AssignmentChange], Awaitable[None]]
AfterChange = Callable[[AssignmentChange, Assignment], Awaitable[None]]


class AssignmentService:
    """Validated writes over an :class:`AssignmentAdmin`, with application hooks.

    The library ships no domain rule: an application plugs its own into
    ``before_change`` (raise to veto; nothing is written) and ``after_change``
    (cache invalidation, audit, notifications). Example, the "last owner" rule::

        async def last_owner(change: AssignmentChange) -> None:
            leaving = change.kind == "revoke" or (
                change.kind == "change_role" and change.new_role != "OWNER"
            )
            if leaving and change.old and change.old.role == "OWNER":
                owners = [
                    a for a in await service.members(change.scope)
                    if a.role == "OWNER" and a.status.value == "active"
                ]
                if len(owners) <= 1:
                    raise LastOwnerRequiredError()

        service = AssignmentService(admin, catalog, before_change=[last_owner])

    Changes of one scope are serialised **within this process** (the veto hooks and
    the write run under a per-scope lock), so concurrent requests cannot both pass
    the same check. Several processes/instances still race (two owners revoking each
    other on different servers): enforce hard invariants in the store as well
    (a constraint or transaction of your own adapter).

    A role is bound to a scope kind through its permissions: every permission of
    the role must belong to the kind of the scope it is assigned in.

    Args:
        admin: The write side of a store.
        catalog: Used to validate roles.
        before_change: Veto hooks, run in order before any write.
        after_change: Hooks run in order after a successful write.
    """

    def __init__(
        self,
        admin: AssignmentAdmin,
        catalog: PermissionCatalog,
        *,
        before_change: Sequence[BeforeChange] = (),
        after_change: Sequence[AfterChange] = (),
    ) -> None:
        self._admin = admin
        self._catalog = catalog
        # One change at a time per scope *in this process*: makes check-then-act
        # veto hooks (last owner...) safe against concurrent requests here. Other
        # processes still race; enforce hard invariants in the store as well.
        self._locks: weakref.WeakValueDictionary[tuple[str, str], asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )
        self._before = tuple(before_change)
        self._after = tuple(after_change)

    def _lock_for(self, scope: ScopeRef) -> asyncio.Lock:
        key = (scope.kind, scope.id)
        lock = self._locks.get(key)
        if lock is None:
            lock = self._locks[key] = asyncio.Lock()
        return lock

    def _validate_role(self, role: str, scope: ScopeRef) -> None:
        if role not in self._catalog.roles():
            raise UnknownRoleError(f"unknown role: {role}")
        for permission in self._catalog.permissions_for(role):
            kind = self._catalog.spec(permission).scope_kind
            if kind != scope.kind:
                raise ScopeKindMismatchError(
                    f"role {role} grants {permission} (scope kind {kind}); "
                    f"cannot be assigned in a {scope.kind} scope"
                )

    async def _old(self, principal_id: str, scope: ScopeRef) -> Assignment | None:
        if isinstance(self._admin, AssignmentStore):
            return await self._admin.get_assignment(principal_id, scope)
        for item in await self._admin.list_for_scope(scope):
            if item.principal_id == principal_id:
                return item
        return None

    async def _run(
        self,
        kind: Literal["assign", "change_role", "revoke"],
        principal_id: str,
        scope: ScopeRef,
        new_role: str | None,
        write: Callable[[], Awaitable[Assignment]],
    ) -> Assignment:
        # The state the hooks judge (``old``) is read inside the scope lock, together
        # with the write, so two changes of one scope cannot interleave here.
        async with self._lock_for(scope):
            change = AssignmentChange(
                kind,
                principal_id,
                scope,
                await self._old(principal_id, scope),
                new_role,
            )
            for hook in self._before:
                await hook(change)
            written = await write()
        # The write is done: every after_change hook runs (cache invalidation must
        # not be skipped because an earlier hook failed); the first error is re-raised.
        first_error: Exception | None = None
        for after in self._after:
            try:
                await after(change, written)
            except Exception as exc:
                logger.opt(exception=True).error("after_change hook failed")
                first_error = first_error or exc
        if first_error is not None:
            raise first_error
        return written

    async def assign(self, principal_id: str, scope: ScopeRef, role: str) -> Assignment:
        """Give ``principal_id`` ``role`` in ``scope``.

        Raises:
            UnknownRoleError: Role not in the catalog.
            ScopeKindMismatchError: Role belongs to another scope kind.
            RevisionConflictError: Already actively assigned.
        """
        self._validate_role(role, scope)
        return await self._run(
            "assign",
            principal_id,
            scope,
            role,
            lambda: self._admin.assign(NewAssignment(principal_id, scope, role)),
        )

    async def change_role(
        self, principal_id: str, scope: ScopeRef, role: str, *, expected_revision: int
    ) -> Assignment:
        """Change the role of an active assignment (optimistic concurrency)."""
        self._validate_role(role, scope)
        return await self._run(
            "change_role",
            principal_id,
            scope,
            role,
            lambda: self._admin.change_role(
                principal_id, scope, role, expected_revision=expected_revision
            ),
        )

    async def revoke(
        self, principal_id: str, scope: ScopeRef, *, expected_revision: int
    ) -> Assignment:
        """Revoke an active assignment (optimistic concurrency)."""
        return await self._run(
            "revoke",
            principal_id,
            scope,
            None,
            lambda: self._admin.revoke(
                principal_id, scope, expected_revision=expected_revision
            ),
        )

    async def members(self, scope: ScopeRef) -> Sequence[Assignment]:
        """Return every assignment of ``scope``."""
        return await self._admin.list_for_scope(scope)
