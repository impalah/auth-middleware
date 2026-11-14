"""Assignment store implementations.

``SqlAssignmentStore`` is imported lazily so that ``import auth_middleware.authz``
never imports SQLAlchemy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from auth_middleware.authz.stores.memory import InMemoryAssignmentStore

if TYPE_CHECKING:  # for type checkers; at runtime these are imported lazily
    from auth_middleware.authz.stores.dynamodb import DynamoDbAssignmentStore
    from auth_middleware.authz.stores.sql import SqlAssignmentStore

__all__ = ["DynamoDbAssignmentStore", "InMemoryAssignmentStore", "SqlAssignmentStore"]


def __getattr__(name: str) -> Any:
    if name == "SqlAssignmentStore":
        from auth_middleware.authz.stores.sql import SqlAssignmentStore

        return SqlAssignmentStore
    if name == "DynamoDbAssignmentStore":
        from auth_middleware.authz.stores.dynamodb import DynamoDbAssignmentStore

        return DynamoDbAssignmentStore
    raise AttributeError(name)
