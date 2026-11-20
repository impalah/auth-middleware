"""SQLAlchemy stores for ABAC: policies and persisted attributes.

Same session-injection shapes, ``before_query`` hook and optimistic ``revision``
as :class:`~auth_middleware.authz.stores.sql.SqlAssignmentStore`:

1. ``async_sessionmaker``: a short session per call (singleton store).
2. A callable returning an async context manager yielding a session.
3. An already open ``AsyncSession``: the store never commits, rolls back or closes it.

A database that is unreachable or throttling is reported as
``StoreUnavailableError`` (the guard answers 503, never an allow).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from loguru import logger

from auth_middleware.authz.abac.types import (
    Effect,
    EntityAttributes,
    EntityRef,
    NewPolicy,
    Policy,
    PolicyScope,
    PolicyStatus,
    validate_attributes,
)
from auth_middleware.authz.errors import (
    AuthzError,
    ConfigurationError,
    InvalidPolicyError,
    PolicyConflictError,
    RevisionConflictError,
    StoreUnavailableError,
)
from auth_middleware.authz.types import ScopeRef

try:
    from ksuid import Ksuid
    from sqlalchemy import MetaData, Table, delete, insert, select, update
    from sqlalchemy.exc import IntegrityError, InterfaceError, OperationalError
    from sqlalchemy.ext.asyncio import AsyncSession
except ImportError as exc:  # pragma: no cover - exercised without the extra
    raise ImportError(
        "the SQL ABAC stores need SQLAlchemy: pip install 'auth-middleware[sqlalchemy]'"
    ) from exc

from auth_middleware.authz.stores.sql_models import (
    DEFAULT_ATTRIBUTE_TABLE,
    DEFAULT_POLICY_TABLE,
    build_attribute_table,
    build_policy_table,
)

BeforeQuery = Callable[["AsyncSession", "ScopeRef | None"], Awaitable[None]]


def _is_duplicate_key(exc: IntegrityError) -> bool:
    text = str(exc.orig).lower()
    return any(m in text for m in ("unique", "duplicate"))


class _SqlBase:
    """Session handling shared by the two stores."""

    def __init__(
        self,
        session_provider: Any,
        *,
        before_query: BeforeQuery | None,
        commit: bool,
    ) -> None:
        self._provider = session_provider
        self._before = before_query
        self._injected = isinstance(session_provider, AsyncSession)
        if not commit and not self._injected:
            raise ConfigurationError(
                "commit=False only makes sense with an injected AsyncSession"
            )
        self._commit = commit and not self._injected

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        if isinstance(self._provider, AsyncSession):
            yield self._provider
        else:
            async with self._provider() as session:
                yield session

    async def _run(
        self, session: AsyncSession, scope: ScopeRef | None, stmt: Any
    ) -> Any:
        try:
            if self._before is not None:
                await self._before(session, scope)
            return await session.execute(stmt)
        except (OperationalError, InterfaceError) as exc:
            raise StoreUnavailableError("the database is unavailable") from exc

    async def _finish(self, session: AsyncSession) -> None:
        if self._commit:
            await session.commit()
        elif self._injected:
            await session.flush()

    async def _insert(
        self, session: AsyncSession, scope: ScopeRef | None, stmt: Any
    ) -> bool:
        """Run an INSERT; ``False`` when it hit a duplicate key."""
        try:
            if self._injected:
                async with session.begin_nested():  # a failed INSERT must not poison it
                    await self._run(session, scope, stmt)
            else:
                await self._run(session, scope, stmt)
        except IntegrityError as exc:
            if not self._injected:
                await session.rollback()
            if not _is_duplicate_key(exc):
                raise
            return False
        return True


def _scope_ref(kind: str, scope_id: str | None) -> ScopeRef | None:
    return None if scope_id is None else ScopeRef(kind, scope_id)


class SqlPolicyStore(_SqlBase):
    """``PolicyStore`` + ``PolicyAdmin`` over a SQL table.

    A stored row that cannot be decoded (a hand-edited table, an old format) is
    returned as a ``deny`` that always applies and logged at ERROR: it fails
    closed instead of silently disappearing.

    Args:
        session_provider: One of the three shapes above.
        table_name: Table name (a plain SQL identifier).
        before_query: Awaited before every statement with the session and the
            scope (``None`` for kind-wide or cross-scope statements): where an
            application binds row-level security. Exceptions propagate.
        commit: Commit after writes when the store owns the session.
    """

    def __init__(
        self,
        session_provider: Any,
        *,
        table_name: str = DEFAULT_POLICY_TABLE,
        before_query: BeforeQuery | None = None,
        commit: bool = True,
    ) -> None:
        super().__init__(session_provider, before_query=before_query, commit=commit)
        self._table: Table = build_policy_table(MetaData(), table_name)

    def _decode(self, row: Any) -> Policy:
        try:
            return Policy(
                id=row.id,
                effect=Effect(row.effect),
                permissions=tuple(row.permissions),
                scope=PolicyScope(row.scope_kind, row.scope_id),
                condition=dict(row.condition_doc),
                description=row.description or "",
                priority=row.priority,
                hide=bool(row.hide),
                enforce=bool(row.enforce),
                status=PolicyStatus(row.status),
                revision=row.revision,
                created_at=_aware(row.created_at),
                updated_at=_aware(row.updated_at),
            )
        except (AuthzError, ValueError, TypeError, KeyError, RecursionError):
            logger.error("stored policy {} cannot be decoded: it fails closed", row.id)
            scope = PolicyScope(row.scope_kind, row.scope_id)
            names = _safe_permissions(row.permissions)
            return Policy.fail_closed(row.id, scope, names)

    async def _fetch(self, session: AsyncSession, policy_id: str) -> Any:
        stmt = select(self._table).where(self._table.c.id == policy_id)
        return (await self._run(session, None, stmt)).first()

    async def get(self, policy_id: str) -> Policy | None:
        async with self._session() as session:
            row = await self._fetch(session, policy_id)
            return None if row is None else self._decode(row)

    async def list_policies(self, scope: ScopeRef) -> Sequence[Policy]:
        t = self._table.c
        stmt = (
            select(self._table)
            .where(
                (t.scope_kind == scope.kind)
                & ((t.scope_id == scope.id) | t.scope_id.is_(None))
                & (t.status == PolicyStatus.ACTIVE.value)
            )
            .order_by(t.priority, t.id)
        )
        async with self._session() as session:
            rows = (await self._run(session, scope, stmt)).all()
            return [self._decode(r) for r in rows]

    async def list_all(self, status: PolicyStatus | None = None) -> Sequence[Policy]:
        stmt = select(self._table).order_by(self._table.c.priority, self._table.c.id)
        if status is not None:
            stmt = stmt.where(self._table.c.status == status.value)
        async with self._session() as session:
            rows = (await self._run(session, None, stmt)).all()
            return [self._decode(r) for r in rows]

    def _values(self, new: NewPolicy) -> dict[str, Any]:
        return {
            "effect": new.effect.value,
            "permissions": list(new.permissions),
            "condition_doc": dict(new.condition),
            "description": new.description,
            "priority": new.priority,
            "hide": new.hide,
            "enforce": new.enforce,
        }

    async def create(self, new: NewPolicy) -> Policy:
        now = datetime.now(UTC)
        stmt = insert(self._table).values(
            id=new.id,
            scope_kind=new.scope.kind,
            scope_id=new.scope.id,
            status=PolicyStatus.ACTIVE.value,
            revision=0,
            created_at=now,
            updated_at=now,
            **self._values(new),
        )
        async with self._session() as session:
            scope = _scope_ref(new.scope.kind, new.scope.id)
            if not await self._insert(session, scope, stmt):
                raise PolicyConflictError(f"policy {new.id!r} already exists")
            row = await self._fetch(session, new.id)
            await self._finish(session)
            return self._decode(row)

    async def _write(
        self, session: AsyncSession, row: Any, expected: int, **values: Any
    ) -> Policy:
        t = self._table.c
        stmt = (
            update(self._table)
            .where((t.id == row.id) & (t.revision == expected))
            .values(revision=expected + 1, updated_at=datetime.now(UTC), **values)
        )
        scope = _scope_ref(row.scope_kind, row.scope_id)
        result = await self._run(session, scope, stmt)
        if result.rowcount != 1:
            raise RevisionConflictError("stale revision")
        fresh = await self._fetch(session, row.id)
        await self._finish(session)
        return self._decode(fresh)

    async def replace(
        self, policy_id: str, new: NewPolicy, *, expected_revision: int
    ) -> Policy:
        async with self._session() as session:
            row = await self._fetch(session, policy_id)
            if row is None or row.revision != expected_revision:
                raise RevisionConflictError("stale revision or unknown policy")
            if new.id != policy_id:
                raise InvalidPolicyError("the id of a policy cannot change")
            if (new.scope.kind, new.scope.id) != (row.scope_kind, row.scope_id):
                raise InvalidPolicyError("the scope of a policy cannot change")
            return await self._write(
                session, row, expected_revision, **self._values(new)
            )

    async def set_status(
        self, policy_id: str, status: PolicyStatus, *, expected_revision: int
    ) -> Policy:
        async with self._session() as session:
            row = await self._fetch(session, policy_id)
            if row is None or row.revision != expected_revision:
                raise RevisionConflictError("stale revision or unknown policy")
            return await self._write(
                session, row, expected_revision, status=status.value
            )


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _safe_permissions(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, (list, tuple)) and raw:
        names = tuple(p for p in raw if isinstance(p, str))
        if names and len(names) == len(raw):
            return names
    return ("*",)


class SqlAttributeStore(_SqlBase):
    """``AttributeStore`` over a SQL table (principal and resource attributes).

    Args:
        session_provider: One of the three shapes in the module docstring.
        table_name: Table name (a plain SQL identifier).
        before_query: Awaited before every statement (``None`` scope).
        commit: Commit after writes when the store owns the session.
    """

    def __init__(
        self,
        session_provider: Any,
        *,
        table_name: str = DEFAULT_ATTRIBUTE_TABLE,
        before_query: BeforeQuery | None = None,
        commit: bool = True,
    ) -> None:
        super().__init__(session_provider, before_query=before_query, commit=commit)
        self._table: Table = build_attribute_table(MetaData(), table_name)

    def _where(self, ref: EntityRef) -> Any:
        t = self._table.c
        return (
            (t.namespace == ref.namespace)
            & (t.kind == ref.kind)
            & (t.entity_id == ref.id)
        )

    @staticmethod
    def _decode(ref: EntityRef, row: Any) -> EntityAttributes:
        return EntityAttributes(ref, dict(row.attributes or {}), row.revision)

    async def _fetch(self, session: AsyncSession, ref: EntityRef) -> Any:
        stmt = select(self._table).where(self._where(ref))
        return (await self._run(session, None, stmt)).first()

    async def get_attributes(self, ref: EntityRef) -> EntityAttributes | None:
        async with self._session() as session:
            row = await self._fetch(session, ref)
            return None if row is None else self._decode(ref, row)

    async def put_attributes(
        self,
        ref: EntityRef,
        attributes: Mapping[str, Any],
        *,
        expected_revision: int | None,
    ) -> EntityAttributes:
        clean = validate_attributes(attributes)
        now = datetime.now(UTC)
        async with self._session() as session:
            if expected_revision is None:
                ins = insert(self._table).values(
                    id=str(Ksuid()),
                    namespace=ref.namespace,
                    kind=ref.kind,
                    entity_id=ref.id,
                    attributes=clean,
                    revision=0,
                    created_at=now,
                    updated_at=now,
                )
                if not await self._insert(session, None, ins):
                    raise RevisionConflictError("attributes already exist")
            else:
                upd = (
                    update(self._table)
                    .where(
                        self._where(ref) & (self._table.c.revision == expected_revision)
                    )
                    .values(
                        attributes=clean,
                        revision=expected_revision + 1,
                        updated_at=now,
                    )
                )
                result = await self._run(session, None, upd)
                if result.rowcount != 1:
                    raise RevisionConflictError("stale revision or no attributes")
            row = await self._fetch(session, ref)
            await self._finish(session)
            return self._decode(ref, row)

    async def delete_attributes(
        self, ref: EntityRef, *, expected_revision: int
    ) -> None:
        stmt = delete(self._table).where(
            self._where(ref) & (self._table.c.revision == expected_revision)
        )
        async with self._session() as session:
            result = await self._run(session, None, stmt)
            if result.rowcount != 1:
                raise RevisionConflictError("stale revision or no attributes")
            await self._finish(session)
