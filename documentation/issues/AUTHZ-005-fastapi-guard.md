# AUTHZ-005 · FastAPI guard `require_permission`

Epic A · Size L · Depends on: 004 · Blocks: 014, 018

## Context

The generic version of ARTISEVM's `require_studio_permission`
(`artisevm/backend/src/artisevm/api/authorization.py`): a dependency factory used 43 times with 32
distinct permissions, which also publishes the permission in OpenAPI as `x-permission`
(`permission_extra`) and returns a context object to the handler. The library's legacy
`require_permissions` takes flat lists and answers a fixed 403; keep it untouched.

## Scope

`src/auth_middleware/authz/guards.py`, `src/auth_middleware/authz/scopes.py`,
`src/auth_middleware/authz/openapi.py`, tests in `tests/authz/test_guards.py`,
`tests/authz/test_openapi.py`.

## Design

```python
def require_permission(
    permission: str,
    *,
    scope: ScopeSource = GlobalScope(),
    authz: Authz | Callable[[Request], Authz] | None = None,
) -> Callable[..., Awaitable[AuthzContext]]: ...
```

`ScopeSource` implementations in `scopes.py`:

- `GlobalScope()` -> `ScopeRef.GLOBAL`.
- `ScopeFromPath(kind: str, param: str)` -> reads `request.path_params[param]`; missing param is a
  programming error (`ConfigurationError` at first call and, when possible, at route registration).
- `ScopeFromCallable(kind: str, fn: Callable[[Request], str | Awaitable[str]])`.

Flow of the returned dependency:

1. Principal: `request.state.current_user` (a `auth_middleware.types.User`). Missing, or
   `user.id == "synthetic"` (the placeholder the middleware creates when authentication is disabled),
   -> `error_policy.unauthenticated(request)` (default 401). `Principal(id=user.id, groups=tuple(await user.groups), email=user.email)`.
2. `scope = await source.resolve(request)`.
3. `authorizer = await authz.authorizer_for(request)` where `authz` defaults to `Authz.of(request)`.
4. `await authorizer.authorize(...)`; map `ScopeNotVisibleError`/`PermissionDeniedError` through the
   error policy and `raise ... from None` (no chained internals in the response).
5. Return the `AuthzContext`; also store it on `request.state.authz_context` for logging/middleware.

Order of dependency evaluation matters for RLS (ARTISEVM binds the tenant in a dependency that must run
**before** the authorizer). The guard must not hide this: document that the store factory is invoked
lazily, at step 3, and that FastAPI resolves sub-dependencies of a factory in declaration order.

OpenAPI (`openapi.py`):

```python
def permission_extra(permission: str) -> dict[str, str]        # {"x-permission": "design.write"}
def declared_permissions(app: FastAPI) -> dict[tuple[str, str], str | None]
    # (METHOD, path) -> value of x-permission, None when absent; used by apps' architecture tests
```

Also export `has_permission(request, permission, scope) -> bool` for use inside handlers (non-raising;
built on `Authorizer.check`).

## Acceptance criteria

- [ ] With the in-memory store: member with permission -> handler runs and receives the context;
  member without -> 403 body `{"detail": {"error": "forbidden", "required_permission": "..."}}`; non-member
  and unknown tenant -> identical 404; no user -> 401 with `WWW-Authenticate: Bearer`; synthetic user -> 401.
- [ ] Group-based platform scope: user whose token groups map to a role holding the permission passes;
  others get 403 (scope kind with `hide_existence=False`).
- [ ] A custom `ErrorPolicy` changes the exceptions raised (test returns a custom exception class).
- [ ] The guard never skips on `AUTH_MIDDLEWARE_DISABLED` (test sets the flag with the explicit allow and
  still sees the user check/401 for the synthetic user).
- [ ] `permission` unknown to the catalog fails **at app startup/first import of the route**, not at
  request time: provide `Authz.validate_routes(app)` which walks the routes, finds guards (mark the
  dependency callable with an attribute `__authz_permission__`) and checks them against the catalog;
  `install` calls it lazily on startup.
- [ ] `declared_permissions` lists every operation of a sample app including ones with no guard.
- [ ] Works when the permission is a `StrEnum` member.
- [ ] Mounted sub-app test: guard with explicit `authz=` works where `app.state.authz` is missing.

## Out of scope

Caching, audit emission, the CLI.
