from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from auth_middleware.authz import NewAssignment, RevisionConflictError, ScopeRef
from auth_middleware.authz.stores import SqlAssignmentStore
from auth_middleware.authz.stores.sql_models import metadata
from auth_middleware.authz.testing import AssignmentStoreContract


@asynccontextmanager
async def sqlite_engine(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/authz.db")

    # SQLAlchemy's documented workaround so SAVEPOINT/ROLLBACK work on pysqlite.
    @event.listens_for(engine.sync_engine, "connect")
    def _connect(dbapi_connection, record):
        dbapi_connection.isolation_level = None

    @event.listens_for(engine.sync_engine, "begin")
    def _begin(conn):
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
def tmp_db(tmp_path):
    return tmp_path


@pytest.mark.asyncio
class TestSqlStoreSessionmaker(AssignmentStoreContract):
    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path):
        self._tmp_path = tmp_path

    @asynccontextmanager
    async def make_store(self):
        async with sqlite_engine(self._tmp_path) as engine:
            yield SqlAssignmentStore(async_sessionmaker(engine, expire_on_commit=False))


@pytest.mark.asyncio
class TestSqlStoreCallableProvider(AssignmentStoreContract):
    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path):
        self._tmp_path = tmp_path

    @asynccontextmanager
    async def make_store(self):
        async with sqlite_engine(self._tmp_path) as engine:
            sm = async_sessionmaker(engine, expire_on_commit=False)
            yield SqlAssignmentStore(lambda: sm())


@pytest.mark.asyncio
async def test_injected_session_never_commits_or_closes(tmp_path):
    async with sqlite_engine(tmp_path) as engine:
        calls: list[str] = []
        async with AsyncSession(engine, expire_on_commit=False) as session:
            for name in ("commit", "rollback", "close"):
                original = getattr(session, name)

                async def spy(*a, _n=name, _o=original, **k):
                    calls.append(_n)
                    return await _o(*a, **k)

                setattr(session, name, spy)
            store = SqlAssignmentStore(session)
            scope = ScopeRef("studio", "s1")
            first = await store.assign(NewAssignment("u", scope, "EDI"))
            await store.change_role("u", scope, "LEC", expected_revision=0)
            await store.revoke("u", scope, expected_revision=1)
            await store.assign(NewAssignment("u", scope, "TIT"))
            assert first.revision == 0
            assert (await store.list_assignments("u"))[0].role == "TIT"
            with pytest.raises(RevisionConflictError):
                await store.assign(NewAssignment("u", scope, "X"))
            assert calls == []
            # the caller decides: roll back and nothing is persisted
            await session.rollback()
        async with AsyncSession(engine) as other:
            assert await SqlAssignmentStore(other).get_assignment("u", scope) is None


@pytest.mark.asyncio
async def test_before_query_runs_before_every_statement(tmp_path):
    async with sqlite_engine(tmp_path) as engine:
        log: list[str] = []

        @event.listens_for(engine.sync_engine, "before_cursor_execute")
        def _sql(conn, cursor, statement, *a):
            log.append("sql:" + statement.split()[0])

        async def before(session, scope):
            log.append(f"before:{scope.id if scope else None}")

        store = SqlAssignmentStore(
            async_sessionmaker(engine, expire_on_commit=False), before_query=before
        )
        scope = ScopeRef("studio", "s1")
        await store.assign(NewAssignment("u", scope, "EDI"))
        await store.list_assignments("u")
        cleaned = [
            e for e in log if e.startswith(("before", "sql:SELECT", "sql:INSERT"))
        ]
        assert cleaned == [
            "before:s1",
            "sql:SELECT",
            "before:s1",
            "sql:INSERT",
            "before:s1",
            "sql:SELECT",
            "before:None",
            "sql:SELECT",
        ]


@pytest.mark.asyncio
async def test_before_query_exception_propagates(tmp_path):
    async with sqlite_engine(tmp_path) as engine:

        async def before(session, scope):
            raise RuntimeError("no tenant bound")

        store = SqlAssignmentStore(async_sessionmaker(engine), before_query=before)
        with pytest.raises(RuntimeError):
            await store.get_assignment("u", ScopeRef("studio", "s1"))


def test_table_name_validated():
    with pytest.raises(ValueError):
        SqlAssignmentStore(object(), table_name="x; DROP TABLE y")


def test_custom_table_name_creates_independent_table():
    store = SqlAssignmentStore(object(), table_name="my_assignments")
    assert store._table.name == "my_assignments"


def test_guard_end_to_end_with_per_request_session(tmp_path, catalog):
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient
    from starlette.middleware.base import BaseHTTPMiddleware

    from auth_middleware.authz import Authz, ScopeFromPath, require_permission
    from auth_middleware.types.user import User

    async def seed():
        async with sqlite_engine(tmp_path) as engine:
            sm = async_sessionmaker(engine, expire_on_commit=False)
            await SqlAssignmentStore(sm).assign(
                NewAssignment("reader", ScopeRef("studio", "s1"), "READER")
            )

    asyncio.run(seed())
    sessions_opened: list[int] = []

    # TestClient runs its own loop: build engine/store inside the app lifespan
    holder: dict = {}

    class Auth(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            who = request.headers.get("x-user")
            if who:
                request.state.current_user = User(id=who, name=who, groups=[])
            return await call_next(request)

    app = FastAPI()
    app.add_middleware(Auth)

    async def factory(request):
        if "engine" not in holder:
            holder["engine"] = create_async_engine(
                f"sqlite+aiosqlite:///{tmp_path}/authz.db"
            )
        session = AsyncSession(holder["engine"], expire_on_commit=False)
        sessions_opened.append(1)
        request.state.session = session
        return SqlAssignmentStore(session)

    Authz.build(catalog=catalog, store_factory=factory).install(app)

    @app.get("/studios/{sid}/d")
    async def d(
        sid: str,
        ctx=Depends(
            require_permission("design.read", scope=ScopeFromPath("studio", "sid"))
        ),
    ):
        return {"ok": True}

    with TestClient(app) as client:
        assert (
            client.get("/studios/s1/d", headers={"x-user": "reader"}).status_code == 200
        )
        assert (
            client.get("/studios/s1/d", headers={"x-user": "other"}).status_code == 404
        )
        client.portal.call(holder["engine"].dispose)
    assert len(sessions_opened) == 2
