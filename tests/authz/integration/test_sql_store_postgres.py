"""Real-PostgreSQL tests. Set AUTHZ_TEST_POSTGRES_URL, e.g.

    docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:17
    AUTHZ_TEST_POSTGRES_URL=postgresql+asyncpg://postgres:pw@localhost:5432/postgres

Each test module works inside its own throwaway schema (and role), dropped at the end.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from auth_middleware.authz import NewAssignment, ScopeRef
from auth_middleware.authz.stores import SqlAssignmentStore
from auth_middleware.authz.stores.sql_models import metadata
from auth_middleware.authz.testing import AssignmentStoreContract

URL = os.environ.get("AUTHZ_TEST_POSTGRES_URL")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL, reason="AUTHZ_TEST_POSTGRES_URL is not set"),
]


@pytest.fixture(scope="module")
def schema():
    name = f"authz_test_{uuid.uuid4().hex[:10]}"
    sync_url = URL.replace("+asyncpg", "+psycopg2")
    eng = create_engine(sync_url, isolation_level="AUTOCOMMIT")
    with eng.connect() as conn:
        conn.execute(text(f'CREATE SCHEMA "{name}"'))
    yield name
    with eng.connect() as conn:
        conn.execute(text(f'DROP SCHEMA "{name}" CASCADE'))
    eng.dispose()


def _async_engine(schema: str):
    return create_async_engine(
        URL, connect_args={"server_settings": {"search_path": schema}}
    )


@asynccontextmanager
async def fresh_engine(schema: str):
    engine = _async_engine(schema)
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
        await conn.run_sync(metadata.create_all)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.mark.asyncio
class TestPostgresContract(AssignmentStoreContract):
    @pytest.fixture(autouse=True)
    def _schema(self, schema):
        self._schema_name = schema

    @asynccontextmanager
    async def make_store(self):
        async with fresh_engine(self._schema_name) as engine:
            yield SqlAssignmentStore(async_sessionmaker(engine, expire_on_commit=False))


@pytest.mark.asyncio
async def test_rls_door(schema):
    """Without a bound scope the store sees nothing; bound, only that scope."""
    role = f"authz_rls_{uuid.uuid4().hex[:8]}"
    async with fresh_engine(schema) as engine:
        admin = async_sessionmaker(engine, expire_on_commit=False)
        seed = SqlAssignmentStore(admin)
        s1, s2 = ScopeRef("studio", "s1"), ScopeRef("studio", "s2")
        await seed.assign(NewAssignment("u", s1, "EDI"))
        await seed.assign(NewAssignment("u", s2, "LEC"))
        async with engine.begin() as conn:
            await conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
            await conn.execute(text(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"'))
            await conn.execute(text(f'GRANT SELECT ON authz_assignment TO "{role}"'))
            await conn.execute(
                text("ALTER TABLE authz_assignment ENABLE ROW LEVEL SECURITY")
            )
            await conn.execute(
                text(
                    "CREATE POLICY by_scope ON authz_assignment FOR SELECT "
                    "USING (scope_id = current_setting('app.scope_id', true))"
                )
            )
        try:

            async def unbound(session, scope):
                await session.execute(text(f'SET LOCAL ROLE "{role}"'))

            async def bound(session, scope):
                await unbound(session, scope)
                if scope is not None:
                    await session.execute(
                        text("SELECT set_config('app.scope_id', :id, true)"),
                        {"id": scope.id},
                    )

            blind = SqlAssignmentStore(admin, before_query=unbound)
            aware = SqlAssignmentStore(admin, before_query=bound)
            assert await blind.get_assignment("u", s1) is None
            assert await blind.list_for_scope(s1) == []
            got = await aware.get_assignment("u", s1)
            assert got is not None and got.role == "EDI"
            assert [a.scope.id for a in await aware.list_for_scope(s2)] == ["s2"]
            # a scope bound to s1 cannot read s2's row
            assert await aware.get_assignment("u", s2) is not None
            async with admin() as session:
                await session.execute(text(f'SET LOCAL ROLE "{role}"'))
                await session.execute(
                    text("SELECT set_config('app.scope_id', 's1', true)")
                )
                rows = (
                    await session.execute(text("SELECT scope_id FROM authz_assignment"))
                ).all()
                assert [r[0] for r in rows] == ["s1"]
        finally:
            async with engine.begin() as conn:
                await conn.execute(text("DROP POLICY by_scope ON authz_assignment"))
                await conn.execute(
                    text("ALTER TABLE authz_assignment DISABLE ROW LEVEL SECURITY")
                )
                await conn.execute(
                    text(f'REVOKE ALL ON authz_assignment FROM "{role}"')
                )
                await conn.execute(
                    text(f'REVOKE USAGE ON SCHEMA "{schema}" FROM "{role}"')
                )
                await conn.execute(text(f'DROP ROLE "{role}"'))


@pytest.mark.asyncio
async def test_injected_session_rolls_back_with_the_caller(schema):
    scope = ScopeRef("studio", "s1")
    async with fresh_engine(schema) as engine:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            async with session.begin():
                store = SqlAssignmentStore(session)
                await store.assign(NewAssignment("u", scope, "EDI"))
                assert await store.get_assignment("u", scope) is not None
                await session.rollback()
        async with AsyncSession(engine) as other:
            assert await SqlAssignmentStore(other).get_assignment("u", scope) is None


def test_migration_round_trip_keeps_legacy_table(schema):
    from alembic import command
    from alembic.config import Config

    root = Path(__file__).parents[3]
    name = f"authz_mig_{uuid.uuid4().hex[:8]}"
    sync_url = URL.replace("+asyncpg", "+psycopg2")
    eng = create_engine(sync_url)
    with eng.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{name}"'))
    mig = create_engine(sync_url, connect_args={"options": f"-csearch_path={name}"})
    try:
        cfg = Config(str(root / "alembic.ini"))
        cfg.set_main_option("script_location", str(root / "alembic"))
        with mig.begin() as conn:
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, "head")
            tables = set(
                conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = :s"
                    ),
                    {"s": name},
                ).scalars()
            )
            assert {"authz_permissions", "authz_assignment"} <= tables
            command.downgrade(cfg, "-1")
            tables = set(
                conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = :s"
                    ),
                    {"s": name},
                ).scalars()
            )
            assert "authz_assignment" not in tables
            assert "authz_permissions" in tables
    finally:
        mig.dispose()
        with eng.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{name}" CASCADE'))
        eng.dispose()
