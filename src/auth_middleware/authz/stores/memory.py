"""In-memory assignment store: tests, examples and reference implementation."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from types import MappingProxyType

from auth_middleware.authz.errors import RevisionConflictError
from auth_middleware.authz.types import (
    Assignment,
    AssignmentStatus,
    NewAssignment,
    ScopeRef,
)

_Key = tuple[str, ScopeRef]


class InMemoryAssignmentStore:
    """Implements ``AssignmentStore`` and ``AssignmentAdmin`` over a dict.

    Writes are serialized with an ``asyncio.Lock``. State is per instance and
    per process; it is a real implementation, not a mock.
    """

    supports_attributes = True

    def __init__(self) -> None:
        self._items: dict[_Key, Assignment] = {}
        self._lock = asyncio.Lock()

    async def get_assignment(
        self, principal_id: str, scope: ScopeRef
    ) -> Assignment | None:
        return self._items.get((principal_id, scope))

    async def list_assignments(self, principal_id: str) -> Sequence[Assignment]:
        return [a for (pid, _), a in self._items.items() if pid == principal_id]

    async def list_for_scope(self, scope: ScopeRef) -> Sequence[Assignment]:
        return [a for (_, sc), a in self._items.items() if sc == scope]

    async def assign(self, new: NewAssignment) -> Assignment:
        key = (new.principal_id, new.scope)
        async with self._lock:
            current = self._items.get(key)
            if current is None:
                created = Assignment(
                    new.principal_id,
                    new.scope,
                    new.role,
                    AssignmentStatus.ACTIVE,
                    0,
                    datetime.now(UTC),
                    MappingProxyType(dict(new.attributes)),
                )
            elif current.status is AssignmentStatus.ACTIVE:
                raise RevisionConflictError("assignment already active")
            else:
                created = replace(
                    current,
                    role=new.role,
                    status=AssignmentStatus.ACTIVE,
                    revision=current.revision + 1,
                    attributes=MappingProxyType(dict(new.attributes)),
                )
            self._items[key] = created
            return created

    async def change_role(
        self, principal_id: str, scope: ScopeRef, role: str, *, expected_revision: int
    ) -> Assignment:
        async with self._lock:
            current = self._require_active(principal_id, scope, expected_revision)
            updated = replace(current, role=role, revision=current.revision + 1)
            self._items[(principal_id, scope)] = updated
            return updated

    async def revoke(
        self, principal_id: str, scope: ScopeRef, *, expected_revision: int
    ) -> Assignment:
        async with self._lock:
            current = self._require_active(principal_id, scope, expected_revision)
            updated = replace(
                current,
                status=AssignmentStatus.REVOKED,
                revision=current.revision + 1,
            )
            self._items[(principal_id, scope)] = updated
            return updated

    def _require_active(
        self, principal_id: str, scope: ScopeRef, expected_revision: int
    ) -> Assignment:
        current = self._items.get((principal_id, scope))
        if (
            current is None
            or current.status is not AssignmentStatus.ACTIVE
            or current.revision != expected_revision
        ):
            raise RevisionConflictError("stale revision or no active assignment")
        return current
