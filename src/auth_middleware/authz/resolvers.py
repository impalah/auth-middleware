"""Role resolvers: where the roles of a principal in a scope come from."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from auth_middleware.authz.ports import AssignmentStore
from auth_middleware.authz.types import (
    GLOBAL_KIND,
    AssignmentStatus,
    Principal,
    ScopeRef,
)


@dataclass(frozen=True, slots=True)
class ResolvedRoles:
    """Roles (and free attributes) a resolver found."""

    roles: frozenset[str]
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.roles)


class RoleResolver(Protocol):
    """Resolves the roles of a principal in a scope, or ``None`` if it knows none."""

    async def resolve(
        self, principal: Principal, scope: ScopeRef
    ) -> ResolvedRoles | None:
        """Return the roles or ``None``."""
        ...


class AssignmentRoleResolver:
    """Roles from a stored, ACTIVE assignment (revoked == absent)."""

    def __init__(self, store: AssignmentStore) -> None:
        """
        Args:
            store: The assignment store to read.
        """
        self._store = store

    async def resolve(
        self, principal: Principal, scope: ScopeRef
    ) -> ResolvedRoles | None:
        assignment = await self._store.get_assignment(principal.id, scope)
        if assignment is None or assignment.status is not AssignmentStatus.ACTIVE:
            return None
        return ResolvedRoles(frozenset({assignment.role}), dict(assignment.attributes))


class GroupRoleResolver:
    """Token groups -> roles, for scopes of one kind."""

    def __init__(
        self, mapping: Mapping[str, str], *, scope_kind: str = GLOBAL_KIND
    ) -> None:
        """
        Args:
            mapping: ``group -> role``.
            scope_kind: Only scopes of this kind are resolved.
        """
        self._mapping = dict(mapping)
        self._scope_kind = scope_kind

    async def resolve(
        self, principal: Principal, scope: ScopeRef
    ) -> ResolvedRoles | None:
        if scope.kind != self._scope_kind:
            return None
        roles = frozenset(
            self._mapping[g] for g in principal.groups if g in self._mapping
        )
        return ResolvedRoles(roles) if roles else None
