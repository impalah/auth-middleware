# AUTHZ-004 · `Authz` runtime and startup injection

Epic A · Size M · Depends on: 003 · Blocks: 005, 012, 013

## Context

Requirement from the owner: the storage backend (SQLAlchemy or DynamoDB) is chosen and injected **at
startup**, not read from globals or the environment by the new code. Also required by ARTISEVM: the
store must be resolvable **per request** so that it can share the request's database session (RLS and
one transaction per request: `artisevm/backend/src/artisevm/composition.py` lines ~190-225,
`get_membership_repo` binds the tenant before the authorizer runs).

## Scope

`src/auth_middleware/authz/runtime.py`, `tests/authz/test_runtime.py`.

## Design

```python
class Authz:
    @classmethod
    def build(
        cls,
        *,
        catalog: PermissionCatalog,
        store: AssignmentStore | None = None,
        store_factory: StoreFactory | None = None,
        group_roles: Mapping[str, str] | None = None,
        group_scope_kind: str = GLOBAL_KIND,
        error_policy: ErrorPolicy | None = None,
        hooks: AuthzHooks | None = None,
    ) -> "Authz": ...

    async def authorizer_for(
        self, request: Request
    ) -> Authorizer: ...  # builds per request from the factory
    def install(
        self, app: FastAPI | Starlette, *, allow_disabled_for_development: bool = False
    ) -> None: ...
    @classmethod
    def of(cls, request: Request) -> "Authz": ...  # reads request.app.state.authz
    async def aclose(self) -> None: ...  # closes stores that own resources
```

Rules:

- Exactly one of `store` / `store_factory` (or neither **only** when `group_roles` is given, a pure
  group-based setup); otherwise `ConfigurationError` at `build`.
- `store` is wrapped as `lambda request: store`. A factory may be sync or async.
- `install` puts the instance in `app.state.authz`, registers shutdown via the app's lifespan/`on_event`
  compatible hook to call `aclose`, and **raises `ConfigurationError` when
  `auth_middleware.settings.AUTH_MIDDLEWARE_DISABLED` is true** unless
  `allow_disabled_for_development=True` (then it logs a WARNING). Reason: the legacy checkers skip every
  check when that flag is set; the new guard must not be silently off.
- `Authz.of(request)` raises `ConfigurationError("authz not installed on this app")` if missing. Mounted
  sub-applications (Starlette `Mount`) have their own `app.state`: document that `install` must be
  called on each app that uses the guard, or the guard takes `authz=` explicitly (AUTHZ-005).
- `ErrorPolicy` and `AuthzHooks` are dataclasses defined here with safe defaults:

```python
@dataclass(frozen=True, slots=True)
class ErrorPolicy:
    not_visible: Callable[[Request, ScopeNotVisibleError], Exception] = (
        default_not_visible  # HTTPException(404)
    )
    denied: Callable[[Request, PermissionDeniedError], Exception] = (
        default_denied  # HTTPException(403, {"error": "forbidden", "required_permission": name})
    )
    unauthenticated: Callable[[Request], Exception] = (
        default_unauthenticated  # HTTPException(401, headers={"WWW-Authenticate": "Bearer"})
    )


@dataclass(frozen=True, slots=True)
class AuthzHooks:
    on_decision: Callable[[DecisionEvent], Awaitable[None] | None] | None = (
        None  # used by AUTHZ-013
    )
```

The default `denied` body shape `{"error": "forbidden", "required_permission": ...}` is deliberate:
it is what ARTISEVM returns today, so its problem handlers keep working (AUTHZ-018 parity).

## Acceptance criteria

- [ ] `build` validates the combinations above with clear messages.
- [ ] A store factory is called once per `authorizer_for` call (test with a counting factory and two
  requests).
- [ ] `install` refuses `AUTH_MIDDLEWARE_DISABLED=True` and accepts it only with the explicit flag.
- [ ] `aclose` is idempotent and closes stores that expose `aclose()`.
- [ ] No module-level singleton or environment read in `authz/` (a test greps the package source for
  `os.environ`/`getenv` and for module-level instances of `Authz`).
- [ ] Works with FastAPI and plain Starlette apps.

## Out of scope

The guard itself (005), caches (012), audit emission (013: only the hook type exists here).
