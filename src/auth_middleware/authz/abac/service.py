"""Policy service: validated, serialised, observable writes over a ``PolicyAdmin``."""

from __future__ import annotations

import asyncio
import inspect
import weakref
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from loguru import logger

from auth_middleware.authz.abac.types import NewPolicy, Policy, PolicyStatus
from auth_middleware.authz.abac.validation import validate_policy
from auth_middleware.authz.catalog import PermissionCatalog
from auth_middleware.authz.errors import InvalidPolicyError
from auth_middleware.authz.ports import PolicyAdmin


@dataclass(frozen=True, slots=True)
class PolicyChange:
    """A change that happened to a policy (given to ``after_change`` hooks)."""

    kind: Literal["create", "replace", "enable", "disable"]
    policy: Policy


AfterChange = Callable[[PolicyChange], Awaitable[None] | None]


class PolicyService:
    """Writes policies after validating them against the catalog.

    Nothing invalid reaches the store: the policy is checked with
    ``validate_policy`` (every problem reported at once) before any write. Writes
    to one policy id are serialised **within this process**; several processes
    still race, which the store's revision check resolves
    (``RevisionConflictError``).

    Args:
        admin: The write side of a policy store.
        catalog: Permissions, scope kinds and attribute schema.
        allow_permit: Accept ``permit`` policies (``grant`` mode).
        after_change: Hooks run after each successful write (cache invalidation:
            ``CachingPolicySource.on_change``; audit; notifications). A failing
            hook is logged and the first error is re-raised after all have run.
    """

    def __init__(
        self,
        admin: PolicyAdmin,
        catalog: PermissionCatalog,
        *,
        allow_permit: bool = False,
        after_change: Sequence[AfterChange] = (),
    ) -> None:
        self._admin = admin
        self._catalog = catalog
        self._allow_permit = allow_permit
        self._after = tuple(after_change)
        self._locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    def _lock_for(self, policy_id: str) -> asyncio.Lock:
        lock = self._locks.get(policy_id)
        if lock is None:
            lock = self._locks[policy_id] = asyncio.Lock()
        return lock

    def _validate(self, new: NewPolicy) -> None:
        validate_policy(new, self._catalog, allow_permit=self._allow_permit)

    async def _notify(self, change: PolicyChange) -> None:
        first: Exception | None = None
        for hook in self._after:
            try:
                result = hook(change)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                logger.opt(exception=True).error("policy after_change hook failed")
                first = first or exc
        if first is not None:
            raise first

    async def create(self, new: NewPolicy) -> Policy:
        """Validate and create a policy.

        Raises:
            InvalidPolicyError: Not valid against the catalog (nothing written).
            PolicyConflictError: The id exists.
        """
        self._validate(new)
        async with self._lock_for(new.id):
            created = await self._admin.create(new)
        await self._notify(PolicyChange("create", created))
        return created

    async def replace(
        self, policy_id: str, new: NewPolicy, *, expected_revision: int
    ) -> Policy:
        """Validate and replace a policy (optimistic concurrency)."""
        if new.id != policy_id:
            raise InvalidPolicyError("the id of a policy cannot change")
        self._validate(new)
        async with self._lock_for(policy_id):
            updated = await self._admin.replace(
                policy_id, new, expected_revision=expected_revision
            )
        await self._notify(PolicyChange("replace", updated))
        return updated

    async def _set_status(
        self,
        policy_id: str,
        status: PolicyStatus,
        expected_revision: int,
        kind: Literal["enable", "disable"],
    ) -> Policy:
        async with self._lock_for(policy_id):
            updated = await self._admin.set_status(
                policy_id, status, expected_revision=expected_revision
            )
        await self._notify(PolicyChange(kind, updated))
        return updated

    async def enable(self, policy_id: str, *, expected_revision: int) -> Policy:
        """Enable a disabled policy."""
        return await self._set_status(
            policy_id, PolicyStatus.ACTIVE, expected_revision, "enable"
        )

    async def disable(self, policy_id: str, *, expected_revision: int) -> Policy:
        """Disable a policy (kept as history; it stops applying)."""
        return await self._set_status(
            policy_id, PolicyStatus.DISABLED, expected_revision, "disable"
        )

    async def get(self, policy_id: str) -> Policy | None:
        """Return a policy (any status) or ``None``."""
        return await self._admin.get(policy_id)
