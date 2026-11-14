# AUTHZ-033 · Policy snapshot cache

Epic H · Size S · Depends on: 027, 029 · Decision Q5: default TTL **5 s** (owner, 2026-11-14)

## Context

ABAC adds one policy read per decision (two `Query` calls on DynamoDB). Policies change rarely, so unlike
assignments (AUTHZ-012, off by default) a short snapshot is reasonable. Staleness only matters after a
policy **change**, and a stale snapshot is at worst the previous policy set.

## Scope

`abac/cache.py`, `tests/authz/abac/test_policy_cache.py`.

## Design

`CachingPolicySource(inner, *, ttl_seconds, max_scopes=1000, clock=time.monotonic)`:
key = `(scope.kind, scope.id)`; value = tuple of policies. TTL cap 60 s unless
`i_understand_stale_authorization=True` (same rule as 012). `invalidate(scope=None)` and automatic
invalidation from `PolicyService.after_change` (all scopes of the policy's kind, or the one scope).
Single-flight: concurrent misses for the same key share one load. Failed loads are **not** cached;
on failure after a previous snapshot the stale snapshot is **not** served (fail closed: 503), unlike
JWKS. `AbacConfig.policy_cache_ttl` defaults to 5.0 (the source is wrapped automatically); 0 disables it.

## Acceptance criteria

- [ ] Fake clock: hit, expiry, eviction of oldest, `invalidate`.
- [ ] 100 concurrent decisions on a cold key -> one store call.
- [ ] Write through `PolicyService` invalidates immediately in the same process.
- [ ] Store failure after a warm cache entry past TTL -> `StoreUnavailableError` (no stale serving).
- [ ] Default build wraps the source with a 5 s TTL; `policy_cache_ttl=0` leaves it unwrapped (tests).
- [ ] Docs warn that other processes see changes only after the TTL.
