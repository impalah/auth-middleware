"""DynamoDB stores for ABAC (policies and persisted attributes), on PynamoDB.

Same conventions as ``DynamoDbAssignmentStore``: blocking PynamoDB calls run in
worker threads, writes are conditional on the optimistic ``revision``, guard-path
reads are consistent, outages become ``StoreUnavailableError``. No GSI is needed.

Key design (one table; two tables, or the assignment table, work as well)::

    Policy       pk=SCOPE#<kind>#<scope id | *>   sk=POLICY#<policy id>
    Id marker    pk=POLICYID#<policy id>          sk=META   (scope of the policy)
    Attributes   pk=ENTITY#<ns>#<kind>#<id>       sk=ATTRS

``list_policies(scope)`` is two consistent ``Query`` calls (the scope's partition and
the kind-wide ``*`` one), no scan. The **id marker** makes policy ids unique across
scopes: it is created first with ``attribute_not_exists`` (a crash between the two
writes leaves an orphan marker that the next ``create`` of that id recovers).
``list_all`` is a ``Scan``: tooling only, never the request path. A policy of the
global scope is stored under ``*`` whether it was created as ``PolicyScope("global")``
or ``PolicyScope("global", "*")``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any, Literal

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
    InvalidPolicyError,
    PolicyConflictError,
    RevisionConflictError,
)
from auth_middleware.authz.stores.dynamodb import blocking_call, connection_meta
from auth_middleware.authz.types import ScopeRef

try:
    from pynamodb.attributes import (
        BooleanAttribute,
        NumberAttribute,
        UnicodeAttribute,
        UTCDateTimeAttribute,
    )
    from pynamodb.constants import PAY_PER_REQUEST_BILLING_MODE
    from pynamodb.exceptions import DoesNotExist
    from pynamodb.models import Model
except ImportError as exc:  # pragma: no cover - exercised without the extra
    raise ImportError(
        "the DynamoDB ABAC stores need PynamoDB: "
        "pip install 'auth-middleware[dynamodb]'"
    ) from exc

DEFAULT_POLICY_TABLE = "authz_policy"
_POLICY = "POLICY#"


def _scope_pk(kind: str, scope_id: str | None) -> str:
    return f"SCOPE#{kind}#{scope_id or '*'}"


def _marker_pk(policy_id: str) -> str:
    return f"POLICYID#{policy_id}"


def _entity_pk(ref: EntityRef) -> str:
    return f"ENTITY#{ref.namespace}#{ref.kind}#{ref.id}"


def _build_model(table_name: str, meta: dict[str, Any]) -> Any:
    meta_attrs = {
        "table_name": table_name,
        "billing_mode": PAY_PER_REQUEST_BILLING_MODE,
    }
    meta_attrs.update(meta)
    meta_cls = type("Meta", (), meta_attrs)

    class Item(Model):  # type: ignore[misc,unused-ignore]
        Meta = meta_cls  # type: ignore[assignment,unused-ignore]
        pk = UnicodeAttribute(hash_key=True)
        sk = UnicodeAttribute(range_key=True)
        policy_id = UnicodeAttribute(null=True)
        effect = UnicodeAttribute(null=True)
        scope_kind = UnicodeAttribute(null=True)
        scope_id = UnicodeAttribute(null=True)
        permissions_json = UnicodeAttribute(null=True)
        condition_json = UnicodeAttribute(null=True)
        description = UnicodeAttribute(null=True)
        priority = NumberAttribute(null=True)
        hide = BooleanAttribute(null=True)
        enforce = BooleanAttribute(null=True)
        status = UnicodeAttribute(null=True)
        attrs_json = UnicodeAttribute(null=True)
        revision = NumberAttribute(default=0)
        created_at = UTCDateTimeAttribute(null=True)
        updated_at = UTCDateTimeAttribute(null=True)

    return Item


class _DynamoBase:
    """Connection settings, worker pool and table helpers shared by both stores."""

    def __init__(
        self,
        *,
        table_name: str,
        region: str | None,
        endpoint_url: str | None,
        connect_timeout_seconds: int,
        read_timeout_seconds: int,
        max_retry_attempts: int,
        aws_access_key_id: str | None,
        aws_secret_access_key: str | None,
        max_workers: int | None,
    ) -> None:
        meta = connection_meta(
            region=region,
            endpoint_url=endpoint_url,
            connect_timeout_seconds=connect_timeout_seconds,
            read_timeout_seconds=read_timeout_seconds,
            max_retry_attempts=max_retry_attempts,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        self._executor = (
            ThreadPoolExecutor(max_workers, thread_name_prefix="authz-dynamodb")
            if max_workers
            else None
        )
        self.table_name = table_name
        self._item = _build_model(table_name, meta)

    async def _call[T](self, fn: Callable[[], T]) -> T:
        return await blocking_call(self._executor, fn)

    async def aclose(self) -> None:
        """Stop the dedicated worker pool, if any."""
        if self._executor is not None:
            self._executor.shutdown(wait=False)

    @staticmethod
    def table_definition(
        table_name: str, *, billing: Literal["PAY_PER_REQUEST"] = "PAY_PER_REQUEST"
    ) -> dict[str, Any]:
        """Return ``boto3`` ``create_table`` keyword arguments (no GSI)."""
        return {
            "TableName": table_name,
            "BillingMode": billing,
            "AttributeDefinitions": [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
        }

    async def create_table_if_missing(self) -> None:
        """Create the table if absent. Dev/tests only; never implicit."""

        def run() -> None:
            if not self._item.exists():
                self._item.create_table(wait=True)

        await self._call(run)


def _dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _utc(value: datetime | None) -> datetime | None:
    return None if value is None else value.astimezone(UTC)


class DynamoDbPolicyStore(_DynamoBase):
    """``PolicyStore`` + ``PolicyAdmin`` over a DynamoDB table.

    Args:
        table_name: Existing table (see :meth:`table_definition`).
        region: AWS region; default from the botocore chain.
        endpoint_url: Custom endpoint (DynamoDB Local, emulators, tests).
        connect_timeout_seconds: botocore connect timeout.
        read_timeout_seconds: botocore read timeout.
        max_retry_attempts: botocore retries (throttling backoff).
        aws_access_key_id: Explicit credentials, for tests only.
        aws_secret_access_key: Explicit credentials, for tests only.
        max_workers: Size of a dedicated thread pool (``None``: the loop's default).
    """

    def __init__(
        self,
        *,
        table_name: str = DEFAULT_POLICY_TABLE,
        region: str | None = None,
        endpoint_url: str | None = None,
        connect_timeout_seconds: int = 5,
        read_timeout_seconds: int = 10,
        max_retry_attempts: int = 5,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        max_workers: int | None = None,
    ) -> None:
        super().__init__(
            table_name=table_name,
            region=region,
            endpoint_url=endpoint_url,
            connect_timeout_seconds=connect_timeout_seconds,
            read_timeout_seconds=read_timeout_seconds,
            max_retry_attempts=max_retry_attempts,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            max_workers=max_workers,
        )

    # ------------------------------------------------------------------ helpers

    def _decode(self, item: Any) -> Policy:
        scope_id = None if item.scope_id in (None, "*") else item.scope_id
        try:
            return Policy(
                id=item.policy_id,
                effect=Effect(item.effect),
                permissions=tuple(json.loads(item.permissions_json)),
                scope=PolicyScope(item.scope_kind, scope_id),
                condition=dict(json.loads(item.condition_json)),
                description=item.description or "",
                priority=int(item.priority or 0),
                hide=bool(item.hide),
                enforce=True if item.enforce is None else bool(item.enforce),
                status=PolicyStatus(item.status),
                revision=int(item.revision),
                created_at=_utc(item.created_at),
                updated_at=_utc(item.updated_at),
            )
        except (AuthzError, ValueError, TypeError, KeyError, RecursionError):
            logger.error("stored policy {} cannot be decoded: it fails closed", item.pk)
            policy_id = str(item.policy_id or item.sk.removeprefix(_POLICY))
            try:
                scope = PolicyScope(item.scope_kind, scope_id)
            except AuthzError:
                scope = PolicyScope("global")
            return Policy.fail_closed(policy_id, scope)

    def _item_get(self, pk: str, sk: str) -> Any | None:
        try:
            return self._item.get(pk, sk, consistent_read=True)
        except DoesNotExist:
            return None

    def _load(self, policy_id: str) -> tuple[Any, Any | None] | None:
        """``(marker, policy item or None)``; ``None`` when the id is unknown."""
        marker = self._item_get(_marker_pk(policy_id), "META")
        if marker is None:
            return None
        pk = _scope_pk(marker.scope_kind, marker.scope_id)
        return marker, self._item_get(pk, _POLICY + policy_id)

    def _fields(self, new: NewPolicy) -> dict[str, Any]:
        return {
            "effect": new.effect.value,
            "permissions_json": _dumps(list(new.permissions)),
            "condition_json": _dumps(dict(new.condition)),
            "description": new.description or None,
            "priority": new.priority,
            "hide": new.hide,
            "enforce": new.enforce,
        }

    # --------------------------------------------------------------------- reads

    async def get(self, policy_id: str) -> Policy | None:
        loaded = await self._call(lambda: self._load(policy_id))
        if loaded is None or loaded[1] is None:
            return None
        return self._decode(loaded[1])

    async def list_policies(self, scope: ScopeRef) -> Sequence[Policy]:
        def run() -> list[Any]:
            found: dict[str, Any] = {}
            for pk in dict.fromkeys(
                [_scope_pk(scope.kind, scope.id), _scope_pk(scope.kind, None)]
            ):
                for item in self._item.query(
                    pk, self._item.sk.startswith(_POLICY), consistent_read=True
                ):
                    found.setdefault(item.sk, item)
            return list(found.values())

        policies = [self._decode(i) for i in await self._call(run)]
        active = [p for p in policies if p.status is PolicyStatus.ACTIVE]
        return sorted(active, key=lambda p: (p.priority, p.id))

    async def list_all(self, status: PolicyStatus | None = None) -> Sequence[Policy]:
        def run() -> list[Any]:
            return list(
                self._item.scan(self._item.sk.startswith(_POLICY), consistent_read=True)
            )

        policies = [self._decode(i) for i in await self._call(run)]
        chosen = [p for p in policies if status in (None, p.status)]
        return sorted(chosen, key=lambda p: (p.priority, p.id))

    # -------------------------------------------------------------------- writes

    async def create(self, new: NewPolicy) -> Policy:
        item_cls = self._item
        marker = item_cls(
            _marker_pk(new.id),
            "META",
            policy_id=new.id,
            scope_kind=new.scope.kind,
            scope_id=new.scope.id or "*",
        )
        try:
            await self._call(
                lambda: marker.save(condition=item_cls.pk.does_not_exist())
            )
        except RevisionConflictError:
            if not await self._recover_orphan(marker):
                raise PolicyConflictError(f"policy {new.id!r} already exists") from None
        now = datetime.now(UTC)
        item = item_cls(
            _scope_pk(new.scope.kind, new.scope.id),
            _POLICY + new.id,
            policy_id=new.id,
            scope_kind=new.scope.kind,
            scope_id=new.scope.id or "*",
            status=PolicyStatus.ACTIVE.value,
            revision=0,
            created_at=now,
            updated_at=now,
            **self._fields(new),
        )
        try:
            await self._call(lambda: item.save(condition=item_cls.pk.does_not_exist()))
        except RevisionConflictError:
            raise PolicyConflictError(f"policy {new.id!r} already exists") from None
        except Exception:
            await self._drop_marker(marker)
            raise
        return self._decode(item)

    async def _recover_orphan(self, marker: Any) -> bool:
        """Re-take a marker whose policy item was never written (a crashed create)."""

        def run() -> bool:
            current = self._load(marker.policy_id)
            if current is None or current[1] is not None:
                return False
            marker.save()  # unconditional: the old marker pointed at nothing
            return True

        return bool(await self._call(run))

    async def _drop_marker(self, marker: Any) -> None:
        try:
            await self._call(lambda: marker.delete())
        except Exception:
            logger.warning("could not remove the id marker of {}", marker.policy_id)

    async def _write(
        self, policy_id: str, expected: int, actions: list[Any], check: Any = None
    ) -> Policy:
        item_cls = self._item
        loaded = await self._call(lambda: self._load(policy_id))
        item = None if loaded is None else loaded[1]
        if item is None or int(item.revision) != expected:
            raise RevisionConflictError("stale revision or unknown policy")
        if check is not None:
            check(item)
        actions = [
            *actions,
            item_cls.revision.add(1),
            item_cls.updated_at.set(datetime.now(UTC)),
        ]
        condition = item_cls.revision == expected
        await self._call(lambda: item.update(actions=actions, condition=condition))
        return self._decode(item)

    async def replace(
        self, policy_id: str, new: NewPolicy, *, expected_revision: int
    ) -> Policy:
        item_cls = self._item
        fields = self._fields(new)
        actions = [
            getattr(item_cls, name).set(value)
            for name, value in fields.items()
            if value is not None
        ]
        if fields["description"] is None:
            actions.append(item_cls.description.remove())

        def check(item: Any) -> None:
            if new.id != policy_id:
                raise InvalidPolicyError("the id of a policy cannot change")
            scope_id = None if item.scope_id == "*" else item.scope_id
            same = (
                new.scope.kind == item.scope_kind and (new.scope.id or None) == scope_id
            )
            if not same:
                raise InvalidPolicyError("the scope of a policy cannot change")

        return await self._write(policy_id, expected_revision, actions, check)

    async def set_status(
        self, policy_id: str, status: PolicyStatus, *, expected_revision: int
    ) -> Policy:
        return await self._write(
            policy_id, expected_revision, [self._item.status.set(status.value)]
        )


class DynamoDbAttributeStore(_DynamoBase):
    """``AttributeStore`` over a DynamoDB table (principal and resource attributes).

    Takes the same connection arguments as :class:`DynamoDbPolicyStore`.
    """

    def __init__(
        self,
        *,
        table_name: str = DEFAULT_POLICY_TABLE,
        region: str | None = None,
        endpoint_url: str | None = None,
        connect_timeout_seconds: int = 5,
        read_timeout_seconds: int = 10,
        max_retry_attempts: int = 5,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        max_workers: int | None = None,
    ) -> None:
        super().__init__(
            table_name=table_name,
            region=region,
            endpoint_url=endpoint_url,
            connect_timeout_seconds=connect_timeout_seconds,
            read_timeout_seconds=read_timeout_seconds,
            max_retry_attempts=max_retry_attempts,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            max_workers=max_workers,
        )

    def _get(self, ref: EntityRef) -> Any | None:
        try:
            return self._item.get(_entity_pk(ref), "ATTRS", consistent_read=True)
        except DoesNotExist:
            return None

    @staticmethod
    def _decode(ref: EntityRef, item: Any) -> EntityAttributes:
        return EntityAttributes(
            ref, json.loads(item.attrs_json or "{}"), int(item.revision)
        )

    async def get_attributes(self, ref: EntityRef) -> EntityAttributes | None:
        item = await self._call(lambda: self._get(ref))
        return None if item is None else self._decode(ref, item)

    async def put_attributes(
        self,
        ref: EntityRef,
        attributes: Mapping[str, Any],
        *,
        expected_revision: int | None,
    ) -> EntityAttributes:
        encoded = _dumps(validate_attributes(attributes))
        item_cls = self._item
        now = datetime.now(UTC)
        if expected_revision is None:
            created = item_cls(
                _entity_pk(ref),
                "ATTRS",
                attrs_json=encoded,
                revision=0,
                created_at=now,
                updated_at=now,
            )
            await self._call(
                lambda: created.save(condition=item_cls.pk.does_not_exist())
            )
            return self._decode(ref, created)
        item = await self._call(lambda: self._get(ref))
        if item is None or int(item.revision) != expected_revision:
            raise RevisionConflictError("stale revision or no attributes")
        actions = [
            item_cls.attrs_json.set(encoded),
            item_cls.revision.add(1),
            item_cls.updated_at.set(now),
        ]
        condition = item_cls.revision == expected_revision
        await self._call(lambda: item.update(actions=actions, condition=condition))
        return self._decode(ref, item)

    async def delete_attributes(
        self, ref: EntityRef, *, expected_revision: int
    ) -> None:
        item = await self._call(lambda: self._get(ref))
        if item is None or int(item.revision) != expected_revision:
            raise RevisionConflictError("stale revision or no attributes")
        condition = self._item.revision == expected_revision
        await self._call(lambda: item.delete(condition=condition))


__all__ = ["DynamoDbAttributeStore", "DynamoDbPolicyStore"]
