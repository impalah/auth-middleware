"""AUTHZ-030: SQLAlchemy ABAC stores on SQLite (contract suite + store specifics)."""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from auth_middleware.authz import ConfigurationError, ScopeRef
from auth_middleware.authz.abac.types import (
    Effect,
    EntityRef,
    NewPolicy,
    PolicyScope,
    PolicyStatus,
)
from auth_middleware.authz.errors import PolicyConflictError, RevisionConflictError
from auth_middleware.authz.stores import SqlAttributeStore, SqlPolicyStore
from auth_middleware.authz.stores.sql_models import metadata
from auth_middleware.authz.testing import AttributeStoreContract, PolicyStoreContract

from ..test_sql_store_unit import sqlite_engine

COND = {"eq": [{"attr": "subject.id"}, "x"]}


def np(pid="p1", **kw):
    return NewPolicy(
        pid,
        Effect.DENY,
        ("design.*",),
        kw.pop("scope", PolicyScope("studio", "s1")),
        COND,
        **kw,
    )


@pytest.mark.asyncio
class TestSqlPolicyContract(PolicyStoreContract):
    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path):
        self._tmp_path = tmp_path

    @asynccontextmanager
    async def make_store(self):
        async with sqlite_engine(self._tmp_path) as engine:
            yield SqlPolicyStore(async_sessionmaker(engine, expire_on_commit=False))

    @asynccontextmanager
    async def make_failing_store(self):
        engine = create_async_engine("sqlite+aiosqlite:////nonexistent-dir/x/authz.db")
        try:
            yield SqlPolicyStore(async_sessionmaker(engine, expire_on_commit=False))
        finally:
            await engine.dispose()


@pytest.mark.asyncio
class TestSqlAttributeContract(AttributeStoreContract):
    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path):
        self._tmp_path = tmp_path

    @asynccontextmanager
    async def make_store(self):
        async with sqlite_engine(self._tmp_path) as engine:
            yield SqlAttributeStore(async_sessionmaker(engine, expire_on_commit=False))

    @asynccontextmanager
    async def make_failing_store(self):
        engine = create_async_engine("sqlite+aiosqlite:////nonexistent-dir/x/authz.db")
        try:
            yield SqlAttributeStore(async_sessionmaker(engine, expire_on_commit=False))
        finally:
            await engine.dispose()


@pytest.mark.asyncio
class TestSqlPolicyCallableProvider(PolicyStoreContract):
    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path):
        self._tmp_path = tmp_path

    @asynccontextmanager
    async def make_store(self):
        async with sqlite_engine(self._tmp_path) as engine:
            sm = async_sessionmaker(engine, expire_on_commit=False)
            yield SqlPolicyStore(lambda: sm())


@pytest.mark.asyncio
async def test_injected_session_never_commits_or_closes_and_survives_a_conflict(
    tmp_path,
):
    async with sqlite_engine(tmp_path) as engine:
        calls: list[str] = []
        async with AsyncSession(engine, expire_on_commit=False) as session:
            for name in ("commit", "rollback", "close"):
                original = getattr(session, name)

                async def spy(*a, _n=name, _o=original, **k):
                    calls.append(_n)
                    return await _o(*a, **k)

                setattr(session, name, spy)
            policies, attrs = SqlPolicyStore(session), SqlAttributeStore(session)
            await policies.create(np())
            with pytest.raises(PolicyConflictError):
                await policies.create(np())  # savepoint: the transaction stays usable
            await policies.set_status("p1", PolicyStatus.DISABLED, expected_revision=0)
            ref = EntityRef.principal("u")
            await attrs.put_attributes(ref, {"a": 1}, expected_revision=None)
            with pytest.raises(RevisionConflictError):
                await attrs.put_attributes(ref, {"a": 2}, expected_revision=None)
            assert (await policies.get("p1")).status is PolicyStatus.DISABLED
            assert calls == []
            await session.rollback()
        async with AsyncSession(engine) as other:
            assert await SqlPolicyStore(other).get("p1") is None
            assert await SqlAttributeStore(other).get_attributes(ref) is None


@pytest.mark.asyncio
async def test_before_query_sees_the_scope_and_exceptions_propagate(tmp_path):
    async with sqlite_engine(tmp_path) as engine:
        seen: list[ScopeRef | None] = []

        async def before(session, scope):
            seen.append(scope)

        store = SqlPolicyStore(
            async_sessionmaker(engine, expire_on_commit=False), before_query=before
        )
        await store.create(np())
        await store.create(np("wide", scope=PolicyScope("studio")))
        await store.list_policies(ScopeRef("studio", "s1"))
        await store.list_all()
        assert ScopeRef("studio", "s1") in seen and None in seen

        async def refuse(session, scope):
            raise RuntimeError("no tenant bound")

        locked = SqlPolicyStore(async_sessionmaker(engine), before_query=refuse)
        with pytest.raises(RuntimeError):
            await locked.get("p1")


def test_configuration_and_identifier_validation():
    with pytest.raises(ValueError):
        SqlPolicyStore(object(), table_name="x; DROP TABLE y")
    with pytest.raises(ValueError):
        SqlAttributeStore(object(), table_name="bad name")
    with pytest.raises(ConfigurationError):
        SqlPolicyStore(object(), commit=False)
    assert (
        SqlPolicyStore(object(), table_name="my_policies")._table.name == "my_policies"
    )


@pytest.mark.asyncio
async def test_undecodable_rows_fail_closed(tmp_path):
    async with sqlite_engine(tmp_path) as engine:
        store = SqlPolicyStore(async_sessionmaker(engine, expire_on_commit=False))
        await store.create(np("healthy"))
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO authz_policy (id, effect, scope_kind, scope_id, permissions, "
                    "condition_doc, description, priority, hide, enforce, status, revision, "
                    "created_at, updated_at) VALUES ('broken', 'deny', 'studio', 's1', "
                    "'[\"design.write\"]', '\"not an object\"', '', 0, 0, 1, 'active', 0, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                )
            )
        got = {p.id: p for p in await store.list_policies(ScopeRef("studio", "s1"))}
        assert set(got) == {"broken", "healthy"}
        broken = got["broken"]
        assert broken.effect is Effect.DENY and broken.permissions == ("design.write",)
        assert broken.condition == {"exists": {"attr": "action.permission"}}


@pytest.mark.asyncio
async def test_tables_are_in_the_shared_metadata():
    assert {"authz_assignment", "authz_policy", "authz_attribute"} <= set(
        metadata.tables
    )


def test_sql_stores_import_lazily_without_loading_sqlalchemy():
    import subprocess
    import sys

    code = (
        "import sys, auth_middleware.authz.stores as s;"
        "print('sqlalchemy' in sys.modules, 'auth_middleware.authz.stores.sql_policy' in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.split() == ["False", "False"]
