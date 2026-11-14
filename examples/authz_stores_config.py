"""How to configure each assignment store (used by the quick-start guide).

Nothing here connects to a database at import time.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request

from auth_middleware.authz import (
    Authz,
    PermissionCatalog,
    PermissionSpec,
    ScopeKind,
)
from auth_middleware.authz.stores import InMemoryAssignmentStore

catalog = PermissionCatalog.from_mapping(
    scopes=[ScopeKind("project")],
    permissions=[
        PermissionSpec("docs.read", "project"),
        PermissionSpec("docs.write", "project"),
    ],
    roles={"EDITOR": ["docs.read", "docs.write"], "VIEWER": ["docs.read"]},
)


def memory_authz() -> Authz:
    """Tests and demos: nothing to install."""
    return Authz.build(catalog=catalog, store=InMemoryAssignmentStore())


def sql_authz(database_url: str) -> Authz:
    """SQL (pip install 'auth-middleware[postgres]' or '[mysql]').

    ``database_url`` e.g. ``postgresql+asyncpg://user:pw@host/db`` or
    ``mysql+aiomysql://user:pw@host/db``. Create the table with the Alembic
    revision shipped in ``alembic/`` or with ``sql_models.metadata``.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from auth_middleware.authz.stores import SqlAssignmentStore

    engine = create_async_engine(database_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    return Authz.build(catalog=catalog, store=SqlAssignmentStore(sessions))


def sql_per_request_authz() -> Authz:
    """SQL sharing the request's own session (one transaction per request)."""
    from auth_middleware.authz.stores import SqlAssignmentStore

    def store_for(request: Request) -> SqlAssignmentStore:
        # `request.state.session` is an AsyncSession opened by your own dependency,
        # which FastAPI must run *before* the permission guard.
        return SqlAssignmentStore(request.state.session)

    return Authz.build(catalog=catalog, store_factory=store_for)


def dynamodb_authz(table_name: str, **options: Any) -> Authz:
    """DynamoDB (pip install 'auth-middleware[dynamodb]').

    The table must exist: ``DynamoDbAssignmentStore.table_definition(name)``
    returns the ``create_table`` arguments. Credentials come from the usual
    AWS chain; ``region`` and ``endpoint_url`` are optional keyword options.
    """
    from auth_middleware.authz.stores import DynamoDbAssignmentStore

    store = DynamoDbAssignmentStore(table_name=table_name, **options)
    return Authz.build(catalog=catalog, store=store)
