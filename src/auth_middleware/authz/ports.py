"""Ports (injection surface) of the scoped-permissions subsystem."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from auth_middleware.authz.types import Assignment, NewAssignment, ScopeRef

if TYPE_CHECKING:
    from starlette.requests import Request

    from auth_middleware.authz.abac.types import (
        EntityAttributes,
        EntityRef,
        NewPolicy,
        Policy,
        PolicyStatus,
    )


@runtime_checkable
class AssignmentStore(Protocol):
    """Read side: what the guard needs.

    Contract (enforced by ``auth_middleware.authz.testing``):

    * ``get_assignment`` returns ``None`` when the scope or the principal does
      not exist; the engine must not be able to tell them apart.
    * A ``REVOKED`` assignment may be returned (history) but the engine treats
      it as absent.
    """

    async def get_assignment(
        self, principal_id: str, scope: ScopeRef
    ) -> Assignment | None:
        """Return the assignment of ``principal_id`` in ``scope`` or ``None``."""
        ...

    async def list_assignments(self, principal_id: str) -> Sequence[Assignment]:
        """Return every assignment of ``principal_id`` (all scopes)."""
        ...


@runtime_checkable
class AssignmentAdmin(Protocol):
    """Write side (optional): used by the service and the CLI.

    Revision semantics: the first revision is 0 and every write bumps it by
    exactly 1. A stale ``expected_revision`` raises ``RevisionConflictError``.
    ``assign`` on an existing active assignment raises ``RevisionConflictError``;
    on a revoked one it reactivates it with ``revision + 1``.
    """

    async def assign(self, new: NewAssignment) -> Assignment:
        """Create (or reactivate) an assignment."""
        ...

    async def change_role(
        self, principal_id: str, scope: ScopeRef, role: str, *, expected_revision: int
    ) -> Assignment:
        """Change the role of an active assignment."""
        ...

    async def revoke(
        self, principal_id: str, scope: ScopeRef, *, expected_revision: int
    ) -> Assignment:
        """Revoke an active assignment."""
        ...

    async def list_for_scope(self, scope: ScopeRef) -> Sequence[Assignment]:
        """Return every assignment of ``scope``."""
        ...


StoreFactory = Callable[["Request"], "AssignmentStore | Awaitable[AssignmentStore]"]


@runtime_checkable
class PolicyStore(Protocol):
    """Read side of the ABAC policies (what the decision point needs).

    Contract (``auth_middleware.authz.testing.contract_abac``): ``list_policies``
    returns the **active** policies of the scope and the kind-wide ones, ordered by
    ``(priority, id)``; nothing of other scopes or kinds.
    """

    async def list_policies(self, scope: ScopeRef) -> Sequence[Policy]:
        """Return the active policies that apply to ``scope``."""
        ...

    async def list_all(self, status: PolicyStatus | None = None) -> Sequence[Policy]:
        """Return every policy (optionally only one status), for tooling."""
        ...


@runtime_checkable
class PolicyAdmin(Protocol):
    """Write side of the policies. Same revision semantics as ``AssignmentAdmin``.

    The scope of a policy is immutable; an unknown id is answered like a stale
    revision (``RevisionConflictError``) so a probe learns nothing.
    """

    async def create(self, new: NewPolicy) -> Policy:
        """Create a policy (``PolicyConflictError`` if the id exists)."""
        ...

    async def replace(
        self, policy_id: str, new: NewPolicy, *, expected_revision: int
    ) -> Policy:
        """Replace the content of a policy."""
        ...

    async def set_status(
        self, policy_id: str, status: PolicyStatus, *, expected_revision: int
    ) -> Policy:
        """Enable or disable a policy."""
        ...

    async def get(self, policy_id: str) -> Policy | None:
        """Return a policy (any status) or ``None``."""
        ...


@runtime_checkable
class AttributeStore(Protocol):
    """Persisted attributes of principals and resources."""

    async def get_attributes(self, ref: EntityRef) -> EntityAttributes | None:
        """Return the attributes of ``ref`` or ``None``."""
        ...

    async def put_attributes(
        self,
        ref: EntityRef,
        attributes: Mapping[str, Any],
        *,
        expected_revision: int | None,
    ) -> EntityAttributes:
        """Create (``expected_revision=None``) or replace with a revision check."""
        ...

    async def delete_attributes(
        self, ref: EntityRef, *, expected_revision: int
    ) -> None:
        """Delete the attributes of ``ref`` (revision-checked)."""
        ...
