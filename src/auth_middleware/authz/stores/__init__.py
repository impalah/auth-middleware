"""Assignment store implementations.

``SqlAssignmentStore`` is imported lazily so that ``import auth_middleware.authz``
never imports SQLAlchemy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from auth_middleware.authz.stores.memory import (
    InMemoryAssignmentStore,
    InMemoryAttributeStore,
    InMemoryPolicyStore,
)

if TYPE_CHECKING:  # for type checkers; at runtime these are imported lazily
    from auth_middleware.authz.stores.dynamodb import DynamoDbAssignmentStore
    from auth_middleware.authz.stores.dynamodb_policy import (
        DynamoDbAttributeStore,
        DynamoDbPolicyStore,
    )
    from auth_middleware.authz.stores.sql import SqlAssignmentStore
    from auth_middleware.authz.stores.sql_policy import (
        SqlAttributeStore,
        SqlPolicyStore,
    )

__all__ = [
    "DynamoDbAssignmentStore",
    "DynamoDbAttributeStore",
    "DynamoDbPolicyStore",
    "InMemoryAssignmentStore",
    "InMemoryAttributeStore",
    "InMemoryPolicyStore",
    "SqlAssignmentStore",
    "SqlAttributeStore",
    "SqlPolicyStore",
]

_LAZY = {
    "SqlPolicyStore": "sql_policy",
    "SqlAttributeStore": "sql_policy",
    "DynamoDbPolicyStore": "dynamodb_policy",
    "DynamoDbAttributeStore": "dynamodb_policy",
}


def __getattr__(name: str) -> Any:
    if name == "SqlAssignmentStore":
        from auth_middleware.authz.stores.sql import SqlAssignmentStore

        return SqlAssignmentStore
    if name == "DynamoDbAssignmentStore":
        from auth_middleware.authz.stores.dynamodb import DynamoDbAssignmentStore

        return DynamoDbAssignmentStore
    if name in _LAZY:
        from importlib import import_module

        module = import_module(f"auth_middleware.authz.stores.{_LAZY[name]}")
        return getattr(module, name)
    raise AttributeError(name)
