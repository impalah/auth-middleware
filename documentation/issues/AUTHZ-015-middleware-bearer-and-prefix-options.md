# AUTHZ-015 · Middleware options: canonical Bearer, path prefix, error responder

Epic F · Size M · Depends on: none · Blocks: 017, 021

## Context

ARTISEVM wraps `JwtAuthMiddleware` with two helpers in
`artisevm/backend/src/artisevm/infrastructure/auth/tokens.py` because the library does not offer these
behaviours:

1. `BearerSchemeOnly`: any non-`Bearer` Authorization scheme on an API path gets a 401 (problem body);
   a `bearer`/`BEARER` spelling is rewritten to `Bearer ` because RFC 7235 says the scheme is
   case-insensitive but the library's check is not (it answered 403 to a valid credential).
   Note 0.6.2 already fixed the 500 for non-Bearer schemes (it now answers the `HTTPBearer` status).
2. `PathScoped`: the root app has other apps mounted inside (platform, public); the root's middleware
   also sees their requests, so the root's audience would reject tokens meant for the platform app. The
   wrapper runs the inner middleware only under a prefix.
3. A uniform 401 body that does not echo the reason (no oracle): `application/problem+json`.

`JwtAuthMiddleware` is a `BaseHTTPMiddleware` subclass (`jwt_auth_middleware.py`). ARTISEVM forbids that
base class in its own code (it buffers streams and cuts contextvars; see its
`tests/architecture/test_middleware_policy.py`, which exempts the library explicitly).

## Scope

`src/auth_middleware/jwt_auth_middleware.py`, `tests/test_jwt_auth_middleware.py` and a new
`tests/test_jwt_auth_middleware_options.py`. Additive keyword-only parameters; defaults keep today's
behaviour exactly.

## Design

```python
JwtAuthMiddleware(app, auth_provider, *args,
                  canonical_bearer_scheme: bool = False,   # case-insensitive scheme -> "Bearer"
                  path_prefix: str | None = None,          # None: all paths (today); "/api/studio/v1": only that subtree
                  error_responder: Callable[[Request, AuthFailure], Response] | None = None,
                  **kwargs)

@dataclass(frozen=True, slots=True)
class AuthFailure:
    status_code: int
    reason: Literal["invalid_token", "bad_scheme", "internal"]   # for logs only; never put it in a body by default
```

- `path_prefix` match: path equals the prefix or starts with `prefix + "/"` (reproduce ARTISEVM's
  `PathScoped`). Paths outside the prefix skip the middleware entirely: `request.state.current_user` is
  **not** set for them (document it).
- `error_responder` replaces the three built-in JSON responses. The default stays `{"detail": ...}`.
- `canonical_bearer_scheme=True` rewrites the header scope before delegating (as ARTISEVM does) so that
  `bearer <token>` is accepted. Non-Bearer schemes keep the 0.6.2 behaviour (their own status) unless the
  responder changes the body.

## Acceptance criteria

- [ ] Default construction passes every existing middleware test unchanged.
- [ ] With `canonical_bearer_scheme=True`: `bearer x`, `BEARER x`, `Bearer x` accepted; `Basic x` -> the
  `HTTPBearer` status; the spelling rewrite does not change other headers.
- [ ] With `path_prefix`: requests outside the prefix reach the app untouched (no user), inside are
  validated; a mounted sub-app test reproduces ARTISEVM's studio/platform audience case with two
  middlewares on two prefixes.
- [ ] `error_responder` is used for invalid token, bad scheme and internal errors, and never receives
  the exception text.
- [ ] Open question to record (no code): a pure-ASGI variant (`JwtAuthASGIMiddleware`) to stop depending
  on `BaseHTTPMiddleware`. Write the pros/cons in "Resolution"; implement only if the owner asks.

## Out of scope

Changing the default responses; the guards (017).
