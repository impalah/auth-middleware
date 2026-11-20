"""In-memory assignment store: tests, examples and reference implementation."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from auth_middleware.authz.abac.types import (
    EntityAttributes,
    EntityRef,
    NewPolicy,
    Policy,
    PolicyStatus,
    validate_attributes,
)
from auth_middleware.authz.errors import (
    InvalidPolicyError,
    PolicyConflictError,
    RevisionConflictError,
)
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


class InMemoryPolicyStore:
    """``PolicyStore`` + ``PolicyAdmin`` over a dict (reference implementation)."""

    def __init__(self) -> None:
        self._items: dict[str, Policy] = {}
        self._lock = asyncio.Lock()

    async def list_policies(self, scope: ScopeRef) -> Sequence[Policy]:
        found = [
            p
            for p in self._items.values()
            if p.status is PolicyStatus.ACTIVE and p.scope.matches(scope)
        ]
        return sorted(found, key=lambda p: (p.priority, p.id))

    async def list_all(self, status: PolicyStatus | None = None) -> Sequence[Policy]:
        found = [p for p in self._items.values() if status in (None, p.status)]
        return sorted(found, key=lambda p: (p.priority, p.id))

    async def get(self, policy_id: str) -> Policy | None:
        return self._items.get(policy_id)

    async def create(self, new: NewPolicy) -> Policy:
        async with self._lock:
            if new.id in self._items:
                raise PolicyConflictError(f"policy {new.id!r} already exists")
            now = datetime.now(UTC)
            created = Policy.from_new(new, created_at=now, updated_at=now)
            self._items[new.id] = created
            return created

    def _current(self, policy_id: str, expected_revision: int) -> Policy:
        current = self._items.get(policy_id)
        if current is None or current.revision != expected_revision:
            raise RevisionConflictError("stale revision or unknown policy")
        return current

    async def replace(
        self, policy_id: str, new: NewPolicy, *, expected_revision: int
    ) -> Policy:
        async with self._lock:
            current = self._current(policy_id, expected_revision)
            if new.id != policy_id:
                raise InvalidPolicyError("the id of a policy cannot change")
            if new.scope != current.scope:
                raise InvalidPolicyError("the scope of a policy cannot change")
            updated = Policy.from_new(
                new,
                status=current.status,
                revision=current.revision + 1,
                created_at=current.created_at,
                updated_at=datetime.now(UTC),
            )
            self._items[policy_id] = updated
            return updated

    async def set_status(
        self, policy_id: str, status: PolicyStatus, *, expected_revision: int
    ) -> Policy:
        async with self._lock:
            current = self._current(policy_id, expected_revision)
            updated = replace(
                current,
                status=status,
                revision=current.revision + 1,
                updated_at=datetime.now(UTC),
            )
            self._items[policy_id] = updated
            return updated


class InMemoryAttributeStore:
    """``AttributeStore`` over a dict (reference implementation)."""

    def __init__(self) -> None:
        self._items: dict[EntityRef, EntityAttributes] = {}
        self._lock = asyncio.Lock()

    async def get_attributes(self, ref: EntityRef) -> EntityAttributes | None:
        return self._items.get(ref)

    async def put_attributes(
        self,
        ref: EntityRef,
        attributes: Mapping[str, Any],
        *,
        expected_revision: int | None,
    ) -> EntityAttributes:
        clean = validate_attributes(attributes)
        async with self._lock:
            current = self._items.get(ref)
            if expected_revision is None:
                if current is not None:
                    raise RevisionConflictError("attributes already exist")
                revision = 0
            elif current is None or current.revision != expected_revision:
                raise RevisionConflictError("stale revision or no attributes")
            else:
                revision = current.revision + 1
            stored = EntityAttributes(ref, MappingProxyType(clean), revision)
            self._items[ref] = stored
            return stored

    async def delete_attributes(
        self, ref: EntityRef, *, expected_revision: int
    ) -> None:
        async with self._lock:
            current = self._items.get(ref)
            if current is None or current.revision != expected_revision:
                raise RevisionConflictError("stale revision or no attributes")
            del self._items[ref]
