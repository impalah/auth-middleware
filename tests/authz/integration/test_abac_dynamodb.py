"""DynamoDB ABAC stores: the contract suites plus store specifics.

Runs on an in-process ``moto`` server by default; ``AUTHZ_TEST_DYNAMODB_ENDPOINT``
points the same tests at DynamoDB Local (``integration`` marker).
"""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager

import pytest

from auth_middleware.authz import ScopeRef
from auth_middleware.authz.abac.types import (
    Effect,
    EntityRef,
    NewPolicy,
    PolicyScope,
    PolicyStatus,
)
from auth_middleware.authz.errors import PolicyConflictError
from auth_middleware.authz.stores import DynamoDbAttributeStore, DynamoDbPolicyStore
from auth_middleware.authz.testing import AttributeStoreContract, PolicyStoreContract

from .test_dynamodb_store import EXTERNAL, endpoint  # noqa: F401

pytestmark = [pytest.mark.integration] if EXTERNAL else []

COND = {"eq": [{"attr": "subject.id"}, "x"]}


def _kw(url: str) -> dict:
    return {
        "region": "us-east-1",
        "endpoint_url": url,
        "aws_access_key_id": "test",
        "aws_secret_access_key": "test",
    }


@asynccontextmanager
async def fresh(cls, url: str, **kw):
    store = cls(table_name=f"abac_{uuid.uuid4().hex[:12]}", **_kw(url), **kw)
    await store.create_table_if_missing()
    try:
        yield store
    finally:
        await asyncio.to_thread(store._item.delete_table)
        await store.aclose()


def np(pid="p1", scope=None, **kw):
    return NewPolicy(
        pid,
        Effect.DENY,
        ("design.*",),
        scope or PolicyScope("studio", "s1"),
        COND,
        **kw,
    )


@pytest.mark.asyncio
class TestDynamoPolicyContract(PolicyStoreContract):
    @pytest.fixture(autouse=True)
    def _endpoint(self, endpoint):  # noqa: F811
        self._url = endpoint

    @asynccontextmanager
    async def make_store(self):
        async with fresh(DynamoDbPolicyStore, self._url) as store:
            yield store

    @asynccontextmanager
    async def make_failing_store(self):
        store = DynamoDbPolicyStore(
            table_name="nowhere",
            region="us-east-1",
            endpoint_url="http://127.0.0.1:1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
            connect_timeout_seconds=1,
            max_retry_attempts=0,
        )
        try:
            yield store
        finally:
            await store.aclose()


@pytest.mark.asyncio
class TestDynamoAttributeContract(AttributeStoreContract):
    @pytest.fixture(autouse=True)
    def _endpoint(self, endpoint):  # noqa: F811
        self._url = endpoint

    @asynccontextmanager
    async def make_store(self):
        async with fresh(DynamoDbAttributeStore, self._url) as store:
            yield store


@pytest.mark.asyncio
async def test_policy_ids_are_unique_across_scopes_even_concurrently(endpoint):  # noqa: F811
    async with fresh(DynamoDbPolicyStore, endpoint) as store:
        results = await asyncio.gather(
            *(
                store.create(np(scope=PolicyScope("studio", f"s{i}")))
                for i in range(10)
            ),
            return_exceptions=True,
        )
        assert sum(1 for r in results if not isinstance(r, Exception)) == 1
        assert all(
            isinstance(r, PolicyConflictError)
            for r in results
            if isinstance(r, Exception)
        )
        assert len(await store.list_all()) == 1


@pytest.mark.asyncio
async def test_guard_path_reads_are_consistent_and_two_queries(endpoint):  # noqa: F811
    async with fresh(DynamoDbPolicyStore, endpoint) as store:
        await store.create(np())
        await store.create(np("wide", scope=PolicyScope("studio")))
        seen: list[dict] = []
        client = store._item._get_connection().connection.client
        client.meta.events.register(
            "provide-client-params.dynamodb.Query",
            lambda params, **kw: seen.append(dict(params)),
        )
        got = await store.list_policies(ScopeRef("studio", "s1"))
        assert [p.id for p in got] == ["p1", "wide"] or {p.id for p in got} == {
            "p1",
            "wide",
        }
        assert len(seen) == 2 and all(p.get("ConsistentRead") is True for p in seen)


@pytest.mark.asyncio
async def test_orphan_marker_from_a_crashed_create_is_recovered(endpoint):  # noqa: F811
    async with fresh(DynamoDbPolicyStore, endpoint) as store:
        marker = store._item(
            "POLICYID#p1", "META", policy_id="p1", scope_kind="studio", scope_id="s1"
        )
        await asyncio.to_thread(marker.save)  # the policy item was never written
        assert await store.get("p1") is None
        created = await store.create(np())
        assert created.id == "p1" and (await store.get("p1")) is not None
        with pytest.raises(PolicyConflictError):
            await store.create(np())


@pytest.mark.asyncio
async def test_global_scope_and_optional_description(endpoint):  # noqa: F811
    async with fresh(DynamoDbPolicyStore, endpoint) as store:
        await store.create(np("g", scope=PolicyScope("global", "*"), description=""))
        got = await store.get("g")
        assert got is not None and got.description == "" and got.scope.id is None
        updated = await store.replace(
            "g",
            np("g", scope=PolicyScope("global"), description="x"),
            expected_revision=0,
        )
        assert updated.description == "x"
        cleared = await store.replace(
            "g", np("g", scope=PolicyScope("global")), expected_revision=1
        )
        assert cleared.description == ""
        assert [p.id for p in await store.list_policies(ScopeRef.GLOBAL)] == ["g"]


@pytest.mark.asyncio
async def test_undecodable_item_fails_closed(endpoint):  # noqa: F811
    async with fresh(DynamoDbPolicyStore, endpoint) as store:
        await store.create(np("ok"))
        broken = store._item(
            "SCOPE#studio#s1",
            "POLICY#broken",
            policy_id="broken",
            effect="deny",
            scope_kind="studio",
            scope_id="s1",
            permissions_json='["design.write"]',
            condition_json="[1, 2",
            status="active",
            revision=0,
        )
        await asyncio.to_thread(broken.save)
        got = {p.id: p for p in await store.list_policies(ScopeRef("studio", "s1"))}
        assert set(got) == {"ok", "broken"}
        assert got["broken"].effect is Effect.DENY
        assert got["broken"].condition == {"exists": {"attr": "action.permission"}}


@pytest.mark.asyncio
async def test_policies_and_attributes_can_share_one_table(endpoint):  # noqa: F811
    table = f"abac_{uuid.uuid4().hex[:12]}"
    policies = DynamoDbPolicyStore(table_name=table, **_kw(endpoint))
    attrs = DynamoDbAttributeStore(table_name=table, **_kw(endpoint))
    await policies.create_table_if_missing()
    try:
        await policies.create(np())
        ref = EntityRef.principal("u1")
        await attrs.put_attributes(ref, {"a": 1}, expected_revision=None)
        assert (await attrs.get_attributes(ref)).attributes == {"a": 1}
        assert [p.id for p in await policies.list_all()] == ["p1"]
        assert (await policies.list_all(PolicyStatus.DISABLED)) == []
    finally:
        await asyncio.to_thread(policies._item.delete_table)
        await policies.aclose()
        await attrs.aclose()


def test_table_definition_has_no_index():
    definition = DynamoDbPolicyStore.table_definition("t")
    assert "GlobalSecondaryIndexes" not in definition
    assert {k["AttributeName"] for k in definition["KeySchema"]} == {"pk", "sk"}
