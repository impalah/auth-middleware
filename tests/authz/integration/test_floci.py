"""The three stores against the three engines, emulated/started by Floci."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_middleware.authz import NewAssignment, ScopeRef
from auth_middleware.authz.stores import SqlAssignmentStore
from auth_middleware.authz.stores.sql_models import metadata
from auth_middleware.authz.testing import AssignmentStoreContract
from tests.authz.integration.floci import FlociStack
from tests.authz.integration.test_dynamodb_store import fresh_store

pytestmark = [pytest.mark.floci]


# -- DynamoDB ---------------------------------------------------------------


@pytest.mark.asyncio
class TestFlociDynamoDb(AssignmentStoreContract):
    @pytest.fixture(autouse=True)
    def _floci(self, floci):
        self._endpoint = floci.endpoint

    @asynccontextmanager
    async def make_store(self):
        async with fresh_store(self._endpoint) as store:
            yield store


@pytest.mark.asyncio
async def test_floci_dynamodb_conditional_writes_and_gsi(floci):
    scope = ScopeRef("studio", "s1")
    async with fresh_store(floci.endpoint) as store:
        first = await store.assign(NewAssignment("u", scope, "EDI"))
        results = await asyncio.gather(
            *(
                store.change_role("u", scope, f"R{i}", expected_revision=first.revision)
                for i in range(8)
            ),
            return_exceptions=True,
        )
        assert sum(1 for r in results if not isinstance(r, Exception)) == 1
        for _ in range(20):  # the GSI may lag
            if await store.list_assignments("u"):
                break
            await asyncio.sleep(0.2)
        assert [a.scope for a in await store.list_assignments("u")] == [scope]


# -- SQL engines behind RDS -------------------------------------------------


@asynccontextmanager
async def _fresh_sql_store(url: str):
    engine = create_async_engine(url, pool_pre_ping=True)
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
        await conn.run_sync(metadata.create_all)
    try:
        yield SqlAssignmentStore(async_sessionmaker(engine, expire_on_commit=False))
    finally:
        await engine.dispose()


@pytest.fixture(scope="module")
def postgres_url(floci: FlociStack):
    url = floci.database_url("postgres", "postgresql+asyncpg")
    yield url
    floci.drop_database("postgres")


@pytest.fixture(scope="module")
def mysql_url(floci: FlociStack):
    url = floci.database_url("mysql", "mysql+aiomysql")
    yield url
    floci.drop_database("mysql")


@pytest.mark.asyncio
class TestFlociPostgres(AssignmentStoreContract):
    @pytest.fixture(autouse=True)
    def _url(self, postgres_url):
        self._db_url = postgres_url

    @asynccontextmanager
    async def make_store(self):
        async with _fresh_sql_store(self._db_url) as store:
            yield store


@pytest.mark.asyncio
class TestFlociMysql(AssignmentStoreContract):
    @pytest.fixture(autouse=True)
    def _url(self, mysql_url):
        self._db_url = mysql_url

    @asynccontextmanager
    async def make_store(self):
        async with _fresh_sql_store(self._db_url) as store:
            yield store
