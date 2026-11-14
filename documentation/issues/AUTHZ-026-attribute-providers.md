# AUTHZ-026 · Attribute providers (subject, resource, environment)

Epic H · Size M · Depends on: 023 · Blocks: 027

## Context

`PLAN-abac.md` section 2.3. The engine must see one flat, read-only `AttributeView`; how each namespace
is filled is pluggable and **lazy** (an attribute no policy mentions is never fetched).

## Scope

`abac/attributes.py`, `abac/environment.py`, `tests/authz/abac/test_attributes.py`.

## Design

```python
class AttributeView(Protocol):
    async def get(self, path: str) -> Any | Absent: ...

class AttributeProvider(Protocol):          # one per namespace, composed by AttributeResolver
    namespaces: frozenset[str]
    async def load(self, ctx: AttributeRequest, needed: frozenset[str]) -> Mapping[str, Any]: ...

@dataclass(frozen=True, slots=True)
class AttributeRequest:  principal: Principal; permission: str; scope: ScopeRef
                         resource: ResourceRef | None; assignment_attributes: Mapping; request: Request | None
```

Providers shipped:

- `PrincipalAttributeProvider`: `subject.id|groups|email|roles`, `subject.claims.<x>` (only names listed
  in `claims_allowlist`; claims come from the `User`/token already on the request), `subject.assignment.<x>`
  (the matched assignment's `attributes`, already merged by the engine).
- `StoredAttributeProvider(store: AttributeStore)`: `subject.attrs.<x>` and `resource.attrs.<x>` from the
  persisted attributes (one `get_attributes` per entity, at most once per decision).
- `LoaderResourceProvider`: `resource.kind|id|attrs.<x>` from the route's loader
  `loader(request, ref) -> Mapping | None`; exceptions -> `StoreUnavailableError`; result validated
  (JSON-able, size) and **cached on the request** for the decision.
- `EnvironmentProvider(clock=utcnow, headers_allowlist=(), trusted_proxies=())`: `env.now`, `env.hour_utc`,
  `env.weekday`, `env.method`, `env.path`, `env.ip` (honours `X-Forwarded-For` **only** from
  `trusted_proxies`), `env.header.<name>` (allow-list only, lower-cased).
- `AttributeResolver(providers)`: collects the paths a policy set needs
  (`needed = union of attr paths of applicable policies`) and calls each provider once, sequentially (same
  rule as resolvers: stores may share a session). Later providers do not override earlier ones: a clash on
  the same path raises `ConfigurationError` at build time (namespaces are disjoint by construction).

Resource loader returning `None` means "no such resource" and surfaces as `ScopeNotVisibleError`
(same answer as a non-member) so a probe cannot tell them apart.

## Acceptance criteria

- [ ] Lazy: a spy provider is not called when no applicable policy references its namespace.
- [ ] Claims not in the allow-list are unreachable (`{"attr": "subject.claims.secret"}` -> rejected by 025
  and absent at runtime).
- [ ] `env.ip` ignores `X-Forwarded-For` from untrusted peers; test with spoofed header.
- [ ] Loader exception -> `StoreUnavailableError` (503 path), loader `None` -> not visible.
- [ ] Per-decision memoisation: the loader is called once even if three policies read it.
- [ ] Clock injection makes time-window tests deterministic.

## Out of scope

Policy evaluation (027).
