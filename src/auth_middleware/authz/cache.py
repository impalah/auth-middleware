"""Optional, short-lived, in-process cache over an assignment store.

Off by default: ``Authz.build`` never wraps a store. Writes made by **other
processes** are only seen after the TTL, so a revoked principal keeps access for
up to ``ttl_seconds`` there. Single event loop assumed; no locks are needed because
dict operations are atomic under the GIL and the loop.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable, Sequence
from typing import Any

from auth_middleware.authz.errors import ConfigurationError
from auth_middleware.authz.ports import AssignmentStore
from auth_middleware.authz.types import Assignment, NewAssignment, ScopeRef

MAX_TTL_SECONDS = 60.0
_Key = tuple[str, str, str]


class CachingAssignmentStore:
    """Decorator over any ``AssignmentStore`` (and ``AssignmentAdmin`` if it is one).

    ``get_assignment`` caches positive and negative results; a negative entry lives
    at most ``ttl_seconds / 4``. Writes through this instance invalidate the
    affected key at once. ``list_assignments`` and ``list_for_scope`` are never
    cached. The key is ``(principal_id, scope.kind, scope.id)``.

    Args:
        inner: The store to wrap.
        ttl_seconds: Entry lifetime; above 60 needs
            ``i_understand_stale_authorization=True``.
        max_entries: Oldest entries are evicted beyond this.
        clock: Monotonic clock (injectable for tests).
        i_understand_stale_authorization: Allow a TTL above 60 s.

    Raises:
        ConfigurationError: Non-positive TTL, or TTL > 60 s without the flag.
    """

    def __init__(
        self,
        inner: AssignmentStore,
        *,
        ttl_seconds: float,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
        i_understand_stale_authorization: bool = False,
    ) -> None:
        if ttl_seconds <= 0:
            raise ConfigurationError("ttl_seconds must be positive")
        if ttl_seconds > MAX_TTL_SECONDS and not i_understand_stale_authorization:
            raise ConfigurationError(
                f"ttl_seconds > {MAX_TTL_SECONDS:g} keeps revoked principals "
                "authorized for that long; pass i_understand_stale_authorization=True"
            )
        self._inner = inner
        self._ttl = ttl_seconds
        self._max = max_entries
        self._clock = clock
        self._entries: dict[_Key, tuple[float, Assignment | None]] = {}
        # Bumped by every invalidation: a read that started before one must not
        # store its (possibly pre-write) result after it.
        self._generation = 0

    @staticmethod
    def _key(principal_id: str, scope: ScopeRef) -> _Key:
        return (principal_id, scope.kind, scope.id)

    def invalidate(self, principal_id: str, scope: ScopeRef | None = None) -> None:
        """Drop one entry, or every entry of ``principal_id`` when ``scope`` is None."""
        self._generation += 1
        if scope is not None:
            self._entries.pop(self._key(principal_id, scope), None)
            return
        for key in [k for k in self._entries if k[0] == principal_id]:
            del self._entries[key]

    async def get_assignment(
        self, principal_id: str, scope: ScopeRef
    ) -> Assignment | None:
        key = self._key(principal_id, scope)
        hit = self._entries.get(key)
        if hit is not None and hit[0] > self._clock():
            return hit[1]
        generation = self._generation
        value = await self._inner.get_assignment(principal_id, scope)
        if generation != self._generation:
            return value  # a write invalidated while we read: do not cache it
        ttl = self._ttl if value is not None else self._ttl / 4
        self._entries.pop(key, None)
        self._entries[key] = (self._clock() + ttl, value)
        while len(self._entries) > self._max:
            del self._entries[next(iter(self._entries))]
        return value

    async def list_assignments(self, principal_id: str) -> Sequence[Assignment]:
        return await self._inner.list_assignments(principal_id)

    # ---- AssignmentAdmin passthrough with invalidation ------------------------

    def _admin(self) -> Any:
        if not all(
            hasattr(self._inner, n)
            for n in ("assign", "change_role", "revoke", "list_for_scope")
        ):
            raise ConfigurationError(
                "the wrapped store does not implement AssignmentAdmin"
            )
        return self._inner

    async def assign(self, new: NewAssignment) -> Assignment:
        try:
            return await self._admin().assign(new)  # type: ignore[no-any-return]
        finally:
            self.invalidate(new.principal_id, new.scope)

    async def change_role(
        self, principal_id: str, scope: ScopeRef, role: str, *, expected_revision: int
    ) -> Assignment:
        try:
            return await self._admin().change_role(  # type: ignore[no-any-return]
                principal_id, scope, role, expected_revision=expected_revision
            )
        finally:
            self.invalidate(principal_id, scope)

    async def revoke(
        self, principal_id: str, scope: ScopeRef, *, expected_revision: int
    ) -> Assignment:
        try:
            return await self._admin().revoke(  # type: ignore[no-any-return]
                principal_id, scope, expected_revision=expected_revision
            )
        finally:
            self.invalidate(principal_id, scope)

    async def list_for_scope(self, scope: ScopeRef) -> Sequence[Assignment]:
        return await self._admin().list_for_scope(scope)  # type: ignore[no-any-return]

    async def aclose(self) -> None:
        """Close the wrapped store if it exposes ``aclose()``."""
        closer = getattr(self._inner, "aclose", None)
        if closer is not None:
            result = closer()
            if inspect.isawaitable(result):
                await result
