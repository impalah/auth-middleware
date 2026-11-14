"""Ports (injection surface) of the scoped-permissions subsystem."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from auth_middleware.authz.types import Assignment, NewAssignment, ScopeRef

if TYPE_CHECKING:
    from starlette.requests import Request


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
