# AUTHZ-028 · `Authz` runtime config and guard `resource=`

Epic H · Size M · Depends on: 027 · Blocks: 036

## Scope

`runtime.py`, `guards.py`, `scopes.py` (resource sources), `openapi.py`, `tests/authz/abac/test_guard_abac.py`.

## Design

- `AbacConfig(policies: PolicySource | Sequence[PolicySource], attributes: AttributeStore | None = None,
  mode="restrict", policy_cache_ttl: float = 5.0, claims_allowlist=(), headers_allowlist=(),
  trusted_proxies=(), clock=...)` frozen dataclass. `Authz.build(..., abac: AbacConfig | None = None)`.
  Nothing reads the environment (same rule as 0.7.0). `build` validates every **static** policy against
  the catalog and fails with `ConfigurationError` listing all problems; store policies are validated when
  written (032) and again, defensively, when loaded (an invalid stored policy is skipped, logged at ERROR
  with its id, and counts as a `deny` for the permissions it names: fail closed).
- Resource sources (in `scopes.py` style): `ResourceFromPath(kind, param, loader=None)`,
  `ResourceFromQuery`, `ResourceFromBody(kind, field)` is **not** offered (reading the body in a
  dependency consumes it; document the pattern with an explicit callable `ResourceSource`).
- `require_permission(permission, *, scope=None, resource: ResourceSource | None = None, authz=None)`.
  Invalid resource id (length/charset) -> same answer as unknown scope (404 via `not_visible`).
- `has_permission(request, permission, scope, *, resource=None, authz=None)`.
- OpenAPI: `x-permission` unchanged; add `x-abac: true` on routes whose guard has a resource source or
  whose permission has applicable policies at startup (cheap static check).
- `Authz.validate_routes` additionally warns when a guard has `resource=` but ABAC is not configured
  (the resource would be ignored): `ConfigurationError` when `strict`.
- `request.state.authz_context` carries `policy_ids`.

## Acceptance criteria

- [ ] End-to-end FastAPI test: studio suspended -> `PUT` is 403 and `GET` is 200 with the same role.
- [ ] Owner-only delete example: `resource.attrs.owner_id == subject.id` via loader.
- [ ] Default `AbacConfig` wraps the policy source in the snapshot cache (5 s); `policy_cache_ttl=0` does not.
- [ ] No `abac=` -> no ABAC import, same OpenAPI as 0.7.0 (snapshot test).
- [ ] Invalid static policy at build -> `ConfigurationError` with every problem.
- [ ] Invalid stored policy -> denial for its permissions + ERROR log (test with a store returning junk).
- [ ] Guard with `resource=` while ABAC disabled -> startup error under `strict`.
- [ ] `AUTH_MIDDLEWARE_DISABLED` still never skips the guard.

## Out of scope

The cache itself (033), audit fields (034). `mode="grant"` is documented as experimental (036).
