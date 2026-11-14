"""DynamoDB assignment store, built on PynamoDB.

PynamoDB is synchronous, so every call runs in a worker thread
(``asyncio.to_thread``) and never blocks the event loop.

Single-table design (on-demand billing recommended):

=============  ============================  ================================
Attribute      Value                         Purpose
=============  ============================  ================================
``pk`` (HASH)  ``SCOPE#<kind>#<id>``         one partition per scope
``sk`` (RANGE) ``PRINCIPAL#<principal_id>``  one item per (scope, principal)
``gsi1pk``     ``PRINCIPAL#<principal_id>``  GSI ``by-principal`` HASH
``gsi1sk``     ``SCOPE#<kind>#<id>``         GSI ``by-principal`` RANGE
=============  ============================  ================================

Payload: ``principal_id``, ``scope_kind``, ``scope_id``, ``role``, ``status``,
``revision`` (N), ``created_at``, ``updated_at`` and ``attrs_json`` (a JSON
string, at most 4 KB, to avoid DynamoDB's float/Decimal map pitfalls).

Consistency: ``get_assignment`` (the guard path) uses ``ConsistentRead=True`` by
default so a just-revoked principal is never admitted. A GSI only supports
eventually consistent reads, so ``list_assignments`` ("my scopes") may lag by a
moment; the guard never uses it. Writes are conditional (optimistic ``revision``).
Use botocore retries (adaptive mode) for throttling; what still fails is raised as
``StoreUnavailableError``.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any, Literal, TypeVar

from auth_middleware.authz.errors import RevisionConflictError, StoreUnavailableError
from auth_middleware.authz.types import (
    Assignment,
    AssignmentStatus,
    NewAssignment,
    ScopeRef,
)

try:
    from pynamodb.attributes import (
        NumberAttribute,
        UnicodeAttribute,
        UTCDateTimeAttribute,
    )
    from pynamodb.constants import PAY_PER_REQUEST_BILLING_MODE
    from pynamodb.exceptions import (
        DoesNotExist,
        PynamoDBConnectionError,
        PynamoDBException,
    )
    from pynamodb.indexes import AllProjection, GlobalSecondaryIndex
    from pynamodb.models import Model
except ImportError as exc:  # pragma: no cover - exercised without the extra
    raise ImportError(
        "the DynamoDB assignment store needs PynamoDB: "
        "pip install 'auth-middleware[dynamodb]'"
    ) from exc

DEFAULT_INDEX_NAME = "by-principal"
MAX_ATTRIBUTES_BYTES = 4096
_UNAVAILABLE_CODES = frozenset(
    {
        "ProvisionedThroughputExceededException",
        "ThrottlingException",
        "RequestLimitExceeded",
        "InternalServerError",
        "ServiceUnavailable",
    }
)
_CONDITIONAL = "ConditionalCheckFailedException"
T = TypeVar("T")


def _scope_key(scope: ScopeRef) -> str:
    return f"SCOPE#{scope.kind}#{scope.id}"


def _principal_key(principal_id: str) -> str:
    return f"PRINCIPAL#{principal_id}"


def _build_models(
    table_name: str, index_name: str, meta: dict[str, Any]
) -> tuple[Any, Any]:
    """Create the PynamoDB model classes bound to a runtime table name."""
    gsi_name = index_name

    class ByPrincipal(GlobalSecondaryIndex):  # type: ignore[type-arg,no-untyped-call]
        class Meta:
            index_name = gsi_name
            projection = AllProjection()

        gsi1pk = UnicodeAttribute(hash_key=True)
        gsi1sk = UnicodeAttribute(range_key=True)

    meta_attrs = {
        "table_name": table_name,
        "billing_mode": PAY_PER_REQUEST_BILLING_MODE,
    }
    meta_attrs.update(meta)
    meta_cls = type("Meta", (), meta_attrs)

    class Item(Model):
        Meta = meta_cls  # type: ignore[assignment]
        pk = UnicodeAttribute(hash_key=True)
        sk = UnicodeAttribute(range_key=True)
        gsi1pk = UnicodeAttribute()
        gsi1sk = UnicodeAttribute()
        principal_id = UnicodeAttribute()
        scope_kind = UnicodeAttribute()
        scope_id = UnicodeAttribute()
        role = UnicodeAttribute()
        status = UnicodeAttribute()
        revision = NumberAttribute(default=0)
        created_at = UTCDateTimeAttribute()
        updated_at = UTCDateTimeAttribute()
        attrs_json = UnicodeAttribute(default="{}")
        by_principal = ByPrincipal()

    return Item, ByPrincipal


class DynamoDbAssignmentStore:
    """``AssignmentStore`` + ``AssignmentAdmin`` over a single DynamoDB table.

    Args:
        table_name: Existing table (see :meth:`table_definition`).
        region: AWS region; default from the botocore chain.
        endpoint_url: Custom endpoint (DynamoDB Local, emulators, tests).
        index_name: Name of the by-principal GSI.
        consistent_read: Consistent reads on ``get_assignment`` (default, and
            required to never admit a just-revoked principal). Turning it off
            accepts staleness: only for callers that explicitly want it.
        connect_timeout_seconds: botocore connect timeout.
        read_timeout_seconds: botocore read timeout.
        max_retry_attempts: botocore retries (throttling backoff).
        aws_access_key_id: Explicit credentials, for tests only; otherwise the
            botocore credential chain is used (nothing is read from code).
        aws_secret_access_key: Explicit credentials, for tests only.
        max_workers: Size of a dedicated thread pool for the blocking PynamoDB calls.
            ``None`` uses the event loop's default executor, shared with the rest of
            the application.
    """

    supports_attributes = True

    def __init__(
        self,
        *,
        table_name: str,
        region: str | None = None,
        endpoint_url: str | None = None,
        index_name: str = DEFAULT_INDEX_NAME,
        consistent_read: bool = True,
        connect_timeout_seconds: int = 5,
        read_timeout_seconds: int = 10,
        max_retry_attempts: int = 5,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        max_workers: int | None = None,
    ) -> None:
        meta: dict[str, Any] = {
            "connect_timeout_seconds": connect_timeout_seconds,
            "read_timeout_seconds": read_timeout_seconds,
            "max_retry_attempts": max_retry_attempts,
        }
        if region:
            meta["region"] = region
        if endpoint_url:
            meta["host"] = endpoint_url
        if aws_access_key_id:
            meta["aws_access_key_id"] = aws_access_key_id
        if aws_secret_access_key:
            meta["aws_secret_access_key"] = aws_secret_access_key
        # A dedicated, bounded pool keeps a slow DynamoDB from starving the other
        # users of the event loop's default executor (and bounds our own concurrency).
        self._executor = (
            ThreadPoolExecutor(max_workers, thread_name_prefix="authz-dynamodb")
            if max_workers
            else None
        )
        self.table_name = table_name
        self.index_name = index_name
        self.consistent_read = consistent_read
        self._item, self._gsi = _build_models(table_name, index_name, meta)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _encode_attributes(attributes: Any) -> str:
        data = json.dumps(dict(attributes), separators=(",", ":"), sort_keys=True)
        if len(data.encode("utf-8")) > MAX_ATTRIBUTES_BYTES:
            raise ValueError(f"attributes larger than {MAX_ATTRIBUTES_BYTES} bytes")
        return data

    async def _call(self, fn: Callable[[], T]) -> T:
        """Run a blocking PynamoDB call in a thread, mapping errors."""
        try:
            if self._executor is None:
                return await asyncio.to_thread(fn)
            return await asyncio.get_running_loop().run_in_executor(self._executor, fn)
        except PynamoDBException as exc:
            code = getattr(exc, "cause_response_code", None)
            if code == _CONDITIONAL:
                raise RevisionConflictError("conditional check failed") from None
            if code in _UNAVAILABLE_CODES or isinstance(exc, PynamoDBConnectionError):
                # throttling, server errors, timeouts and unreachable endpoints
                raise StoreUnavailableError("DynamoDB is unavailable") from None
            raise

    def _to_assignment(self, item: Any) -> Assignment:
        return Assignment(
            principal_id=item.principal_id,
            scope=ScopeRef(item.scope_kind, item.scope_id),
            role=item.role,
            status=AssignmentStatus(item.status),
            revision=int(item.revision),
            created_at=item.created_at.astimezone(UTC),
            attributes=json.loads(item.attrs_json or "{}"),
        )

    def _get(self, principal_id: str, scope: ScopeRef) -> Any | None:
        try:
            return self._item.get(
                _scope_key(scope),
                _principal_key(principal_id),
                consistent_read=self.consistent_read,
            )
        except DoesNotExist:
            return None

    # --------------------------------------------------------------------- reads

    async def get_assignment(
        self, principal_id: str, scope: ScopeRef
    ) -> Assignment | None:
        item = await self._call(lambda: self._get(principal_id, scope))
        return None if item is None else self._to_assignment(item)

    async def list_for_scope(self, scope: ScopeRef) -> Sequence[Assignment]:
        def run() -> list[Any]:
            return list(
                self._item.query(
                    _scope_key(scope),
                    self._item.sk.startswith("PRINCIPAL#"),
                    consistent_read=True,
                )
            )

        return [self._to_assignment(i) for i in await self._call(run)]

    async def list_assignments(self, principal_id: str) -> Sequence[Assignment]:
        """List a principal's scopes via the GSI (eventually consistent)."""

        def run() -> list[Any]:
            return list(
                self._item.by_principal.query(
                    _principal_key(principal_id),
                    self._item.gsi1sk.startswith("SCOPE#"),
                )
            )

        return [self._to_assignment(i) for i in await self._call(run)]

    # -------------------------------------------------------------------- writes

    async def assign(self, new: NewAssignment) -> Assignment:
        attrs = self._encode_attributes(new.attributes)
        existing = await self._call(lambda: self._get(new.principal_id, new.scope))
        now = datetime.now(UTC)
        item_cls = self._item
        if existing is None:
            item = item_cls(
                _scope_key(new.scope),
                _principal_key(new.principal_id),
                gsi1pk=_principal_key(new.principal_id),
                gsi1sk=_scope_key(new.scope),
                principal_id=new.principal_id,
                scope_kind=new.scope.kind,
                scope_id=new.scope.id,
                role=new.role,
                status=AssignmentStatus.ACTIVE.value,
                revision=0,
                created_at=now,
                updated_at=now,
                attrs_json=attrs,
            )
            await self._call(lambda: item.save(condition=item_cls.pk.does_not_exist()))
            return self._to_assignment(item)
        if existing.status == AssignmentStatus.ACTIVE.value:
            raise RevisionConflictError("assignment already active")
        return await self._update(
            existing,
            expected=int(existing.revision),
            required_status=AssignmentStatus.REVOKED.value,
            actions=[
                item_cls.role.set(new.role),
                item_cls.status.set(AssignmentStatus.ACTIVE.value),
                item_cls.attrs_json.set(attrs),
            ],
        )

    async def _update(
        self, item: Any, *, expected: int, required_status: str, actions: list[Any]
    ) -> Assignment:
        item_cls = self._item
        condition = (item_cls.revision == expected) & (
            item_cls.status == required_status
        )
        actions = [
            *actions,
            item_cls.revision.add(1),
            item_cls.updated_at.set(datetime.now(UTC)),
        ]
        await self._call(lambda: item.update(actions=actions, condition=condition))
        return self._to_assignment(item)

    async def _mutate(
        self,
        principal_id: str,
        scope: ScopeRef,
        expected_revision: int,
        actions: list[Any],
    ) -> Assignment:
        item = await self._call(lambda: self._get(principal_id, scope))
        if (
            item is None
            or item.status != AssignmentStatus.ACTIVE.value
            or int(item.revision) != expected_revision
        ):
            raise RevisionConflictError("stale revision or no active assignment")
        return await self._update(
            item,
            expected=expected_revision,
            required_status=AssignmentStatus.ACTIVE.value,
            actions=actions,
        )

    async def change_role(
        self, principal_id: str, scope: ScopeRef, role: str, *, expected_revision: int
    ) -> Assignment:
        return await self._mutate(
            principal_id, scope, expected_revision, [self._item.role.set(role)]
        )

    async def revoke(
        self, principal_id: str, scope: ScopeRef, *, expected_revision: int
    ) -> Assignment:
        return await self._mutate(
            principal_id,
            scope,
            expected_revision,
            [self._item.status.set(AssignmentStatus.REVOKED.value)],
        )

    # ---------------------------------------------------------------- operations

    async def aclose(self) -> None:
        """Stop the dedicated worker pool, if any (PynamoDB manages its client)."""
        if self._executor is not None:
            self._executor.shutdown(wait=False)

    @staticmethod
    def table_definition(
        table_name: str,
        *,
        billing: Literal["PAY_PER_REQUEST"] = "PAY_PER_REQUEST",
        index_name: str = DEFAULT_INDEX_NAME,
    ) -> dict[str, Any]:
        """Return ``boto3`` ``create_table`` keyword arguments for the table."""
        return {
            "TableName": table_name,
            "BillingMode": billing,
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
                    "IndexName": index_name,
                    "KeySchema": [
                        {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi1sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        }

    async def create_table_if_missing(self) -> None:
        """Create the table (and GSI) if absent. Dev/tests only; never implicit."""

        def run() -> None:
            if not self._item.exists():
                self._item.create_table(wait=True)

        await self._call(run)


__all__ = ["DynamoDbAssignmentStore"]
