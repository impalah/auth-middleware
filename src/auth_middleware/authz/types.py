"""Dependency-free vocabulary of the scoped-permissions subsystem."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar

GLOBAL_KIND = "global"
MAX_ID_LENGTH = 200
#: Longest principal id (token ``sub``) any store can hold (SQL VARCHAR(500)).
MAX_PRINCIPAL_ID_LENGTH = 500
_KIND_RE = re.compile(r"[a-z][a-z0-9_]*")


@dataclass(frozen=True, slots=True)
class ScopeRef:
    """Reference to a scope (a tenant, a project, the whole platform...).

    Args:
        kind: Scope kind, matching ``[a-z][a-z0-9_]*``.
        id: Scope identifier, non-empty, at most 200 characters. ``"*"`` is only
            valid for the ``global`` kind.

    Raises:
        ValueError: If the kind or the id are invalid.
    """

    kind: str
    id: str
    GLOBAL: ClassVar[ScopeRef]

    def __post_init__(self) -> None:
        if not _KIND_RE.fullmatch(self.kind):
            raise ValueError(f"invalid scope kind: {self.kind!r}")
        if not self.id:
            raise ValueError("scope id must not be empty")
        if len(self.id) > MAX_ID_LENGTH:
            raise ValueError(f"scope id longer than {MAX_ID_LENGTH} characters")
        if self.id == "*" and self.kind != GLOBAL_KIND:
            raise ValueError("'*' is only valid as the id of the global scope")


ScopeRef.GLOBAL = ScopeRef(GLOBAL_KIND, "*")


class AssignmentStatus(StrEnum):
    """Lifecycle status of an assignment."""

    ACTIVE = "active"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is acting: the token ``sub`` plus optional token groups and e-mail."""

    id: str
    groups: tuple[str, ...] = ()
    email: str | None = None


@dataclass(frozen=True, slots=True)
class Assignment:
    """A principal holding a role in a scope.

    ``revision`` starts at 0 and grows by exactly 1 on every write.
    ``attributes`` is free data a store may attach (e.g. a tenant status).
    """

    principal_id: str
    scope: ScopeRef
    role: str
    status: AssignmentStatus
    revision: int = 0
    created_at: datetime | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(
            (self.principal_id, self.scope, self.role, self.status, self.revision)
        )


@dataclass(frozen=True, slots=True)
class NewAssignment:
    """Input of :meth:`AssignmentAdmin.assign`."""

    principal_id: str
    scope: ScopeRef
    role: str
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.principal_id, self.scope, self.role))


class DecisionKind(StrEnum):
    """Outcome of an authorization check."""

    ALLOWED = "allowed"
    NOT_VISIBLE = "not_visible"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class AuthzContext:
    """What a handler receives after a successful check."""

    principal: Principal
    scope: ScopeRef
    roles: frozenset[str]
    permissions: frozenset[str]
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.principal, self.scope, self.roles))
