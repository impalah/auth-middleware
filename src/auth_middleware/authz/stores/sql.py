"""SQLAlchemy assignment store (injected session, tenant-aware, optimistic writes)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from auth_middleware.authz.errors import ConfigurationError, RevisionConflictError
from auth_middleware.authz.types import (
    Assignment,
    AssignmentStatus,
    NewAssignment,
    ScopeRef,
)

try:
    from ksuid import Ksuid
    from sqlalchemy import MetaData, Table, insert, select, update
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.ext.asyncio import AsyncSession
except ImportError as exc:  # pragma: no cover - exercised without the extra
    raise ImportError(
        "the SQL assignment store needs SQLAlchemy: "
        "pip install 'auth-middleware[sqlalchemy]'"
    ) from exc

from auth_middleware.authz.stores.sql_models import DEFAULT_TABLE_NAME, build_table

BeforeQuery = Callable[["AsyncSession", "ScopeRef | None"], Awaitable[None]]


def _is_duplicate_key(exc: IntegrityError) -> bool:
    """Whether an IntegrityError is a unique/duplicate-key violation (any backend)."""
    text = str(exc.orig).lower()
    return any(m in text for m in ("unique", "duplicate"))


class SqlAssignmentStore:
    """``AssignmentStore`` + ``AssignmentAdmin`` over a SQL table.

    Three ways to inject a session:

    1. ``async_sessionmaker``: a short session per call (singleton store).
    2. A callable returning an async context manager yielding a session.
    3. An already open ``AsyncSession`` (per-request store built by a
       ``StoreFactory``): the store never commits, rolls back or closes it, so
       reads and writes happen in the caller's transaction.

    Args:
        session_provider: One of the three shapes above.
        table_name: Table name (a plain SQL identifier).
        before_query: Awaited before every statement with the session and the
            scope (``None`` for the cross-scope ``list_assignments``). This is
            where an application binds row-level security. Exceptions propagate.
        commit: Commit after writes when the store owns the session. Forced off
            for an injected open session.
    """

    supports_attributes = True

    def __init__(
        self,
        session_provider: Any,
        *,
        table_name: str = DEFAULT_TABLE_NAME,
        before_query: BeforeQuery | None = None,
        commit: bool = True,
    ) -> None:
        self._provider = session_provider
        self._table: Table = build_table(MetaData(), table_name)
        self._before = before_query
        self._injected = isinstance(session_provider, AsyncSession)
        if not commit and not self._injected:
            # An owned session that is never committed silently discards writes
            # (while ``assign`` would still return the re-read row).
            raise ConfigurationError(
                "commit=False only makes sense with an injected AsyncSession"
            )
        self._commit = commit and not self._injected

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        provider = self._provider
        if isinstance(provider, AsyncSession):
            yield provider
        else:  # async_sessionmaker or a callable returning an async context manager
            async with provider() as session:
                yield session

    async def _run(
        self, session: AsyncSession, scope: ScopeRef | None, stmt: Any
    ) -> Any:
        if self._before is not None:
            await self._before(session, scope)
        return await session.execute(stmt)

    def _where(self, principal_id: str, scope: ScopeRef) -> Any:
        t = self._table.c
        return (
            (t.principal_id == principal_id)
            & (t.scope_kind == scope.kind)
            & (t.scope_id == scope.id)
        )

    def _to_assignment(self, row: Any) -> Assignment:
        created = row.created_at
        if created is not None and created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        return Assignment(
            principal_id=row.principal_id,
            scope=ScopeRef(row.scope_kind, row.scope_id),
            role=row.role,
            status=AssignmentStatus(row.status),
            revision=row.revision,
            created_at=created,
            attributes=dict(row.attributes or {}),
        )

    async def _fetch(
        self, session: AsyncSession, principal_id: str, scope: ScopeRef
    ) -> Any:
        stmt = select(self._table).where(self._where(principal_id, scope))
        return (await self._run(session, scope, stmt)).first()

    async def get_assignment(
        self, principal_id: str, scope: ScopeRef
    ) -> Assignment | None:
        async with self._session() as session:
            row = await self._fetch(session, principal_id, scope)
            return None if row is None else self._to_assignment(row)

    async def list_assignments(self, principal_id: str) -> Sequence[Assignment]:
        async with self._session() as session:
            stmt = select(self._table).where(self._table.c.principal_id == principal_id)
            rows = (await self._run(session, None, stmt)).all()
            return [self._to_assignment(r) for r in rows]

    async def list_for_scope(self, scope: ScopeRef) -> Sequence[Assignment]:
        async with self._session() as session:
            t = self._table.c
            stmt = select(self._table).where(
                (t.scope_kind == scope.kind) & (t.scope_id == scope.id)
            )
            rows = (await self._run(session, scope, stmt)).all()
            return [self._to_assignment(r) for r in rows]

    async def assign(self, new: NewAssignment) -> Assignment:
        async with self._session() as session:
            row = await self._fetch(session, new.principal_id, new.scope)
            now = datetime.now(UTC)
            if row is None:
                await self._insert(session, new, now)
            elif row.status == AssignmentStatus.ACTIVE:
                raise RevisionConflictError("assignment already active")
            else:
                await self._write(
                    session,
                    row,
                    row.revision,
                    role=new.role,
                    status=AssignmentStatus.ACTIVE.value,
                    attributes=dict(new.attributes),
                )
            # Re-read inside the transaction, before committing: our row is locked by
            # our own write, so the result cannot show another writer's changes.
            result = await self._reload(session, new.principal_id, new.scope)
            await self._finish(session)
            return result

    async def _insert(
        self, session: AsyncSession, new: NewAssignment, now: datetime
    ) -> None:
        stmt = insert(self._table).values(
            id=str(Ksuid()),
            principal_id=new.principal_id,
            scope_kind=new.scope.kind,
            scope_id=new.scope.id,
            role=new.role,
            status=AssignmentStatus.ACTIVE.value,
            revision=0,
            created_at=now,
            updated_at=now,
            attributes=dict(new.attributes),
        )
        try:
            if self._injected:
                # A failed INSERT must not poison the caller's transaction.
                async with session.begin_nested():
                    await self._run(session, new.scope, stmt)
            else:
                await self._run(session, new.scope, stmt)
        except IntegrityError as exc:
            if not self._injected:
                await session.rollback()
            # Only a duplicate key is a revision conflict; a CHECK/NOT NULL/length
            # violation is a real error and must not be mislabelled.
            if not _is_duplicate_key(exc):
                raise
            raise RevisionConflictError("assignment already exists") from None

    async def _write(
        self, session: AsyncSession, row: Any, expected: int, **values: Any
    ) -> None:
        t = self._table.c
        stmt = (
            update(self._table)
            .where((t.id == row.id) & (t.revision == expected))
            .values(revision=expected + 1, updated_at=datetime.now(UTC), **values)
        )
        result = await self._run(session, ScopeRef(row.scope_kind, row.scope_id), stmt)
        if result.rowcount != 1:
            raise RevisionConflictError("stale revision")

    async def _finish(self, session: AsyncSession) -> None:
        if self._commit:
            await session.commit()
        elif self._injected:
            await session.flush()

    async def _reload(
        self, session: AsyncSession, principal_id: str, scope: ScopeRef
    ) -> Assignment:
        row = await self._fetch(session, principal_id, scope)
        if row is None:  # pragma: no cover - defensive
            raise RevisionConflictError("assignment vanished")
        return self._to_assignment(row)

    async def _mutate(
        self,
        principal_id: str,
        scope: ScopeRef,
        expected_revision: int,
        **values: Any,
    ) -> Assignment:
        async with self._session() as session:
            row = await self._fetch(session, principal_id, scope)
            if (
                row is None
                or row.status != AssignmentStatus.ACTIVE
                or row.revision != expected_revision
            ):
                raise RevisionConflictError("stale revision or no active assignment")
            await self._write(session, row, expected_revision, **values)
            result = await self._reload(session, principal_id, scope)
            await self._finish(session)
            return result

    async def change_role(
        self, principal_id: str, scope: ScopeRef, role: str, *, expected_revision: int
    ) -> Assignment:
        return await self._mutate(principal_id, scope, expected_revision, role=role)

    async def revoke(
        self, principal_id: str, scope: ScopeRef, *, expected_revision: int
    ) -> Assignment:
        return await self._mutate(
            principal_id,
            scope,
            expected_revision,
            status=AssignmentStatus.REVOKED.value,
        )
