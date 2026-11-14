# AUTHZ-017 · `require_authenticated` and `get_identity`

Epic F · Size S · Depends on: 015 · Blocks: 021

## Context

ARTISEVM duplicates, in `api/dependencies.py` and `platform_api/dependencies.py`, the same trio:
`require_auth` (fail-closed: a real user must exist; `user.id == "synthetic"` is the placeholder the
middleware creates when authentication is disabled), `current_actor` (the `sub`) and `current_identity`
(`sub`, e-mail, name, groups as a frozen dataclass). The library has `require_user()` /
`get_current_user()` in `guards/functions.py` (lines ~134-165, verified): `require_user` raises `401` for a missing user,
but when `AUTH_MIDDLEWARE_DISABLED` is set it returns the synthetic user and lets the request through
(by design, "never blocked"). The new guard must stay closed for the synthetic user by default.

## Scope

`src/auth_middleware/guards/functions.py` (additions), `src/auth_middleware/types/identity.py`,
`tests/guards/test_authenticated.py`.

## Design

```python
@dataclass(frozen=True, slots=True)
class Identity:
    sub: str
    email: str
    name: str
    groups: tuple[str, ...]


def require_authenticated(
    *,
    allow_synthetic: bool = False,
    on_unauthenticated: Callable[[Request], Exception] | None = None,
) -> Callable[..., Awaitable[User]]: ...
def get_identity(
    *,
    allow_synthetic: bool = False,
    on_unauthenticated: Callable[[Request], Exception] | None = None,
) -> Callable[..., Awaitable[Identity]]: ...
```

- Missing user -> 401 `Authentication required` with `WWW-Authenticate: Bearer` (same as the legacy
  guards); synthetic user -> 401 unless `allow_synthetic=True`.
- `Identity.name` falls back to `sub` when absent; `email` is `""` when absent (matches ARTISEVM so its
  call sites do not change).
- `on_unauthenticated` lets an application raise its own exception (uniform problem body); AUTHZ-004's
  `ErrorPolicy.unauthenticated` should be reused by `require_permission` via the same hook name.

## Acceptance criteria

- [ ] Existing `require_user`/`get_current_user` tests unchanged and green.
- [ ] Table tests: no user, synthetic user, real user, user without e-mail/name, custom responder.
- [ ] `Identity.groups` resolves the lazy `await user.groups`.
- [ ] Docs: `pages_source/functions.rst` documents both.

## Out of scope

Authorization (that is `require_permission`).
