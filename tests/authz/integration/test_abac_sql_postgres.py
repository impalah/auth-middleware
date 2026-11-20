"""Real-PostgreSQL contract run of the ABAC SQL stores (AUTHZ_TEST_POSTGRES_URL)."""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from auth_middleware.authz.stores import SqlAttributeStore, SqlPolicyStore
from auth_middleware.authz.testing import AttributeStoreContract, PolicyStoreContract

from .test_sql_store_postgres import URL, fresh_engine, schema  # noqa: F401

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL, reason="AUTHZ_TEST_POSTGRES_URL is not set"),
]


@pytest.mark.asyncio
class TestPostgresPolicyContract(PolicyStoreContract):
    @pytest.fixture(autouse=True)
    def _schema(self, schema):  # noqa: F811
        self._schema_name = schema

    @asynccontextmanager
    async def make_store(self):
        async with fresh_engine(self._schema_name) as engine:
            yield SqlPolicyStore(async_sessionmaker(engine, expire_on_commit=False))


@pytest.mark.asyncio
class TestPostgresAttributeContract(AttributeStoreContract):
    @pytest.fixture(autouse=True)
    def _schema(self, schema):  # noqa: F811
        self._schema_name = schema

    @asynccontextmanager
    async def make_store(self):
        async with fresh_engine(self._schema_name) as engine:
            yield SqlAttributeStore(async_sessionmaker(engine, expire_on_commit=False))
