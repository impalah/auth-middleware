"""Short-lived snapshot cache of the policies of a scope."""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from typing import Any

from auth_middleware.authz.abac.types import Policy, PolicyStatus
from auth_middleware.authz.errors import ConfigurationError
from auth_middleware.authz.ports import PolicyStore
from auth_middleware.authz.types import ScopeRef

MAX_TTL_SECONDS = 60.0
_Key = tuple[str, str]


class CachingPolicySource:
    """Caches ``list_policies`` per ``(kind, id)`` for a few seconds.

    Policies change rarely, so unlike assignments a short snapshot is reasonable.
    **Other processes see a change only after the TTL**; changes made through this
    instance (``PolicyService.after_change`` -> :meth:`on_change`) show at once.

    Failed loads are not cached and an expired entry is never served when the
    reload fails (fail closed: the guard answers 503), unlike the JWKS cache.
    Concurrent misses for one key share a single load. An ``invalidate`` that
    happens while a load is in flight wins: the stale result is not stored.

    Args:
        inner: The real source.
        ttl_seconds: Seconds an entry lives (> 0; <= 60 unless
            ``i_understand_stale_authorization``).
        max_scopes: Entries kept; the oldest is evicted.
        clock: Monotonic clock (inject a fake in tests).
        i_understand_stale_authorization: Allow a TTL above 60 s.
    """

    def __init__(
        self,
        inner: PolicyStore,
        *,
        ttl_seconds: float,
        max_scopes: int = 1000,  # pragma: no mutate  (a default value)
        clock: Callable[[], float] = time.monotonic,
        i_understand_stale_authorization: bool = False,
    ) -> None:
        if ttl_seconds <= 0:
            raise ConfigurationError("ttl_seconds must be positive")
        if ttl_seconds > MAX_TTL_SECONDS and not i_understand_stale_authorization:
            raise ConfigurationError(
                f"ttl_seconds above {MAX_TTL_SECONDS:g} needs "
                "i_understand_stale_authorization=True"
            )
        if max_scopes < 1:
            raise ConfigurationError("max_scopes must be >= 1")
        self.inner = inner
        self._ttl = ttl_seconds
        self._max = max_scopes
        self._clock = clock
        self._entries: OrderedDict[_Key, tuple[float, tuple[Policy, ...]]] = (
            OrderedDict()
        )
        self._locks: dict[_Key, asyncio.Lock] = {}
        self._generation = 0  # pragma: no mutate  (any start works)

    def _fresh(self, key: _Key) -> tuple[Policy, ...] | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry[0] <= self._clock():
            del self._entries[key]
            return None
        return entry[1]

    async def list_policies(self, scope: ScopeRef) -> Sequence[Policy]:
        key = (scope.kind, scope.id)
        hit = self._fresh(
            key
        )  # pragma: no mutate  (the re-check under the lock covers it)
        if hit is not None:
            return hit
        lock = self._locks.setdefault(
            key, asyncio.Lock()
        )  # pragma: no mutate  (a shared lock only costs speed)
        async with lock:
            hit = self._fresh(key)
            if hit is not None:
                return hit
            generation = self._generation
            value = tuple(await self.inner.list_policies(scope))
            if generation == self._generation:
                self._entries[key] = (self._clock() + self._ttl, value)
                while len(self._entries) > self._max:
                    self._entries.popitem(
                        last=False
                    )  # pragma: no mutate  (falsy last is the same)
            if len(self._locks) > 2 * self._max:  # pragma: no mutate  (housekeeping)
                self._locks = {k: v for k, v in self._locks.items() if v.locked()}
            return value

    async def list_all(self, status: PolicyStatus | None = None) -> Sequence[Policy]:
        return await self.inner.list_all(status)

    def invalidate(self, scope: ScopeRef | None = None) -> None:
        """Drop one scope's entry, or everything when ``scope`` is ``None``."""
        self._generation += 1  # pragma: no mutate  (only inequality matters)
        if scope is None:
            self._entries.clear()
        else:
            self._entries.pop((scope.kind, scope.id), None)

    def invalidate_kind(self, kind: str) -> None:
        """Drop every entry of a scope kind (a kind-wide policy changed)."""
        self._generation += 1  # pragma: no mutate  (only inequality matters)
        for key in [k for k in self._entries if k[0] == kind]:
            del self._entries[key]

    def on_change(self, change: Any) -> None:
        """``PolicyService.after_change`` hook: invalidate what the change touched."""
        policy = change.policy
        if policy.scope.id is None:
            self.invalidate_kind(policy.scope.kind)
        else:
            self.invalidate(ScopeRef(policy.scope.kind, policy.scope.id))

    async def aclose(self) -> None:
        """Close the inner source if it exposes ``aclose()``."""
        closer = getattr(self.inner, "aclose", None)
        if closer is not None:
            result = closer()
            if hasattr(result, "__await__"):
                await result
