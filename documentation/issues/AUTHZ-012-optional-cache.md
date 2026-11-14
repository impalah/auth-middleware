# AUTHZ-012 · Optional short-lived cache

Epic D · Size S · Depends on: 004 · Open question: **Q1** (answer needed before coding)

## Context

ARTISEVM today reads the membership from PostgreSQL on every request (no cache) so a revoked member
loses access immediately. A cache is an optimisation that some adopters will want (DynamoDB reads cost
money); it must never be on by default.

## Decide first

Q1: is a cache acceptable at all for ARTISEVM? If **no**, still implement it for other adopters but do
not enable it in ARTISEVM (AUTHZ-018 leaves it off). Record the answer in "Resolution".

## Scope

`src/auth_middleware/authz/cache.py`, `tests/authz/test_cache.py`.

## Design

```python
class CachingAssignmentStore:  # decorator over any AssignmentStore (and Admin)
    def __init__(
        self,
        inner: AssignmentStore,
        *,
        ttl_seconds: float,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None: ...
    def invalidate(self, principal_id: str, scope: ScopeRef | None = None) -> None: ...

    # get_assignment: cache positive AND negative results for ttl (negative TTL capped at ttl/4)
```

- In-process only (a `dict` + insertion-order eviction). **No shared cache backend** in this issue
  (Valkey/Redis is out of scope; the port for it can come later).
- Writes through the same decorator (`AssignmentAdmin` methods) invalidate the affected keys
  immediately; `AssignmentService.after_change` (AUTHZ-011) can also call `invalidate`.
- Writes from **other processes** are only seen after the TTL: document this loudly. Hard cap on TTL:
  `ttl_seconds <= 60` unless `i_understand_stale_authorization=True`.
- `list_assignments` is not cached.
- Never cache across principals or scopes; key is `(principal_id, scope.kind, scope.id)`.
- Thread/async safety: single event loop assumption, documented; guarded by no locks (dict operations
  are atomic under the GIL and the loop), but a test with 100 concurrent tasks proves no corruption.

## Acceptance criteria

- [ ] With a fake clock: hit within ttl, miss after ttl, negative entry expires sooner.
- [ ] `invalidate` and write-through invalidation work; revocation through the same instance is
  visible at once.
- [ ] `max_entries` evicts the oldest.
- [ ] TTL above 60 s without the explicit flag raises `ConfigurationError`.
- [ ] Default configuration of `Authz.build` uses no cache (a test asserts the store is not wrapped).

## Out of scope

Distributed invalidation.
