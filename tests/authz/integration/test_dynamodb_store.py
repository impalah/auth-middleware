"""DynamoDB store tests.

By default they run against an in-process ``moto`` server (no Docker). Set
``AUTHZ_TEST_DYNAMODB_ENDPOINT`` (e.g. ``http://localhost:8000`` for
``amazon/dynamodb-local``) to run the very same tests against it; those runs carry
the ``integration`` marker.
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from contextlib import asynccontextmanager

import pytest

from auth_middleware.authz import (
    AssignmentStatus,
    NewAssignment,
    RevisionConflictError,
    ScopeRef,
    StoreUnavailableError,
)
from auth_middleware.authz.stores import DynamoDbAssignmentStore
from auth_middleware.authz.testing import AssignmentStoreContract

EXTERNAL = os.environ.get("AUTHZ_TEST_DYNAMODB_ENDPOINT")
pytestmark = [pytest.mark.integration] if EXTERNAL else []


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def endpoint():
    if EXTERNAL:
        yield EXTERNAL
        return
    from moto.server import ThreadedMotoServer

    port = _free_port()
    server = ThreadedMotoServer(port=port, verbose=False)
    server.start()
    yield f"http://127.0.0.1:{port}"
    server.stop()


def _store(endpoint: str, table: str, **kw) -> DynamoDbAssignmentStore:
    return DynamoDbAssignmentStore(
        table_name=table,
        region="us-east-1",
        endpoint_url=endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        **kw,
    )


@asynccontextmanager
async def fresh_store(endpoint: str, **kw):
    store = _store(endpoint, f"authz_{uuid.uuid4().hex[:12]}", **kw)
    await store.create_table_if_missing()
    try:
        yield store
    finally:
        await asyncio.to_thread(store._item.delete_table)
        await store.aclose()


@pytest.mark.asyncio
class TestDynamoContract(AssignmentStoreContract):
    @pytest.fixture(autouse=True)
    def _endpoint(self, endpoint):
        self._endpoint_url = endpoint

    @asynccontextmanager
    async def make_store(self):
        async with fresh_store(self._endpoint_url) as store:
            yield store


@pytest.mark.asyncio
async def test_get_after_revoke_sees_revoked_and_sends_consistent_read(endpoint):
    scope = ScopeRef("studio", "s1")
    async with fresh_store(endpoint) as store:
        seen: list[dict] = []
        client = store._item._get_connection().connection.client
        client.meta.events.register(
            "provide-client-params.dynamodb.GetItem",
            lambda params, **kw: seen.append(dict(params)),
        )
        first = await store.assign(NewAssignment("u", scope, "EDI"))
        await store.revoke("u", scope, expected_revision=first.revision)
        got = await store.get_assignment("u", scope)
        assert got is not None and got.status is AssignmentStatus.REVOKED
        assert seen and all(p.get("ConsistentRead") is True for p in seen)


@pytest.mark.asyncio
async def test_concurrent_change_role_has_one_winner(endpoint):
    scope = ScopeRef("studio", "s1")
    async with fresh_store(endpoint) as store:
        first = await store.assign(NewAssignment("u", scope, "EDI"))
        results = await asyncio.gather(
            *(
                store.change_role("u", scope, f"R{i}", expected_revision=first.revision)
                for i in range(10)
            ),
            return_exceptions=True,
        )
        assert sum(1 for r in results if not isinstance(r, Exception)) == 1
        assert all(
            isinstance(r, RevisionConflictError)
            for r in results
            if isinstance(r, Exception)
        )


@pytest.mark.asyncio
async def test_list_for_scope_paginates_past_one_megabyte(endpoint):
    scope = ScopeRef("studio", "big")
    async with fresh_store(endpoint) as store:
        item_cls = store._item
        from datetime import UTC, datetime

        payload = '{"pad":"' + "x" * 1000 + '"}'
        now = datetime.now(UTC)

        def seed() -> None:
            with item_cls.batch_write() as batch:
                for i in range(1500):
                    batch.save(
                        item_cls(
                            f"SCOPE#{scope.kind}#{scope.id}",
                            f"PRINCIPAL#p{i}",
                            gsi1pk=f"PRINCIPAL#p{i}",
                            gsi1sk=f"SCOPE#{scope.kind}#{scope.id}",
                            principal_id=f"p{i}",
                            scope_kind=scope.kind,
                            scope_id=scope.id,
                            role="EDI",
                            status="active",
                            revision=0,
                            created_at=now,
                            updated_at=now,
                            attrs_json=payload,
                        )
                    )

        await asyncio.to_thread(seed)
        listed = await store.list_for_scope(scope)
        assert len(listed) == 1500
        assert len({a.principal_id for a in listed}) == 1500


@pytest.mark.asyncio
async def test_gsi_lists_principal_scopes_eventually(endpoint):
    async with fresh_store(endpoint) as store:
        for sid in ("a", "b"):
            await store.assign(NewAssignment("u", ScopeRef("studio", sid), "EDI"))
        got: list = []
        for _ in range(20):  # the GSI is eventually consistent
            got = list(await store.list_assignments("u"))
            if len(got) == 2:
                break
            await asyncio.sleep(0.2)
        assert {a.scope.id for a in got} == {"a", "b"}


@pytest.mark.asyncio
async def test_table_definition_matches_what_pynamodb_creates(endpoint):
    async with fresh_store(endpoint) as store:
        described = await asyncio.to_thread(
            lambda: store._item._get_connection().connection.describe_table(
                store.table_name
            )
        )
    definition = DynamoDbAssignmentStore.table_definition(store.table_name)
    table = described["Table"] if "Table" in described else described
    assert {tuple(sorted(k.items())) for k in table["KeySchema"]} == {
        tuple(sorted(k.items())) for k in definition["KeySchema"]
    }
    gsi = table["GlobalSecondaryIndexes"][0]
    assert gsi["IndexName"] == definition["GlobalSecondaryIndexes"][0]["IndexName"]
    assert {tuple(sorted(k.items())) for k in gsi["KeySchema"]} == {
        tuple(sorted(k.items()))
        for k in definition["GlobalSecondaryIndexes"][0]["KeySchema"]
    }
    assert gsi["Projection"]["ProjectionType"] == "ALL"


def test_table_definition_golden():
    assert DynamoDbAssignmentStore.table_definition("t") == {
        "TableName": "t",
        "BillingMode": "PAY_PER_REQUEST",
        "AttributeDefinitions": [
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi1pk", "AttributeType": "S"},
            {"AttributeName": "gsi1sk", "AttributeType": "S"},
        ],
        "KeySchema": [
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "by-principal",
                "KeySchema": [
                    {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi1sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    }


@pytest.mark.asyncio
async def test_hash_in_ids_is_unambiguous_and_oversized_attributes_rejected(endpoint):
    async with fresh_store(endpoint) as store:
        a, b = ScopeRef("studio", "a#b"), ScopeRef("studio", "a")
        await store.assign(NewAssignment("u#1", a, "R1"))
        await store.assign(NewAssignment("u", b, "R2"))
        assert (await store.get_assignment("u#1", a)).role == "R1"
        assert (await store.get_assignment("u", b)).role == "R2"
        assert await store.get_assignment("u#1", b) is None
        assert [x.principal_id for x in await store.list_for_scope(a)] == ["u#1"]
        with pytest.raises(ValueError):
            await store.assign(
                NewAssignment("u", ScopeRef("studio", "a"), "R", {"blob": "x" * 5000})
            )


@pytest.mark.asyncio
async def test_throttling_maps_to_store_unavailable(endpoint):
    from botocore.exceptions import ClientError
    from pynamodb.exceptions import GetError

    def boom(*args, **kwargs):
        cause = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException"}}, "GetItem"
        )
        raise GetError("throttled", cause)

    async with fresh_store(endpoint) as store:
        store._item.get = boom
        with pytest.raises(StoreUnavailableError):
            await store.get_assignment("u", ScopeRef("studio", "a"))


def test_import_error_message_names_the_extra(monkeypatch):
    import builtins
    import importlib
    import sys

    real = builtins.__import__

    def fake(name, *a, **k):
        if name.startswith("pynamodb"):
            raise ImportError("no pynamodb")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    monkeypatch.delitem(sys.modules, "auth_middleware.authz.stores.dynamodb")
    with pytest.raises(ImportError, match=r"auth-middleware\[dynamodb\]"):
        importlib.import_module("auth_middleware.authz.stores.dynamodb")
