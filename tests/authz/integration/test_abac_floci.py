"""The ABAC stores against the three engines, emulated/started by Floci."""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_middleware.authz.stores import (
    DynamoDbAttributeStore,
    DynamoDbPolicyStore,
    SqlAttributeStore,
    SqlPolicyStore,
)
from auth_middleware.authz.stores.sql_models import metadata
from auth_middleware.authz.testing import AttributeStoreContract, PolicyStoreContract

from .test_abac_dynamodb import fresh
from .test_floci import mysql_url, postgres_url  # noqa: F401  (module fixtures)

pytestmark = [pytest.mark.floci]


@asynccontextmanager
async def _fresh_sql(url: str, cls):
    engine = create_async_engine(url, pool_pre_ping=True)
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
        await conn.run_sync(metadata.create_all)
    try:
        yield cls(async_sessionmaker(engine, expire_on_commit=False))
    finally:
        await engine.dispose()


@pytest.mark.asyncio
class TestFlociDynamoPolicies(PolicyStoreContract):
    @pytest.fixture(autouse=True)
    def _floci(self, floci):
        self._endpoint = floci.endpoint

    @asynccontextmanager
    async def make_store(self):
        async with fresh(DynamoDbPolicyStore, self._endpoint) as store:
            yield store


@pytest.mark.asyncio
class TestFlociDynamoAttributes(AttributeStoreContract):
    @pytest.fixture(autouse=True)
    def _floci(self, floci):
        self._endpoint = floci.endpoint

    @asynccontextmanager
    async def make_store(self):
        async with fresh(DynamoDbAttributeStore, self._endpoint) as store:
            yield store


@pytest.mark.asyncio
class TestFlociPostgresPolicies(PolicyStoreContract):
    @pytest.fixture(autouse=True)
    def _url(self, postgres_url):  # noqa: F811
        self._db_url = postgres_url

    @asynccontextmanager
    async def make_store(self):
        async with _fresh_sql(self._db_url, SqlPolicyStore) as store:
            yield store


@pytest.mark.asyncio
class TestFlociPostgresAttributes(AttributeStoreContract):
    @pytest.fixture(autouse=True)
    def _url(self, postgres_url):  # noqa: F811
        self._db_url = postgres_url

    @asynccontextmanager
    async def make_store(self):
        async with _fresh_sql(self._db_url, SqlAttributeStore) as store:
            yield store


@pytest.mark.asyncio
class TestFlociMysqlPolicies(PolicyStoreContract):
    @pytest.fixture(autouse=True)
    def _url(self, mysql_url):  # noqa: F811
        self._db_url = mysql_url

    @asynccontextmanager
    async def make_store(self):
        async with _fresh_sql(self._db_url, SqlPolicyStore) as store:
            yield store


@pytest.mark.asyncio
class TestFlociMysqlAttributes(AttributeStoreContract):
    @pytest.fixture(autouse=True)
    def _url(self, mysql_url):  # noqa: F811
        self._db_url = mysql_url

    @asynccontextmanager
    async def make_store(self):
        async with _fresh_sql(self._db_url, SqlAttributeStore) as store:
            yield store
