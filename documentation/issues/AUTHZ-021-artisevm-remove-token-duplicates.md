# AUTHZ-021 · ARTISEVM: drop the `tokens.py` duplicates

Epic G · Size M · **Repo: artisevm** · Depends on: library 015, 016, 017 released; ARTISEVM 020

Same ARTISEVM rules as AUTHZ-018.

## Context

`backend/src/artisevm/infrastructure/auth/tokens.py` (201 lines) re-implements on top of the library:
`BearerSchemeOnly`, `PathScoped`/`_ScopedJwtAuth`, `AccessTokenOidcProvider` (access-token-only and forced
JWKS refresh), the refusal of `AUTH_MIDDLEWARE_DISABLED`, `oidc_provider_settings` and
`install_oidc_auth`. `api/auth.py` re-exports them; `api/dependencies.py` and
`platform_api/dependencies.py` duplicate `require_auth`, `current_actor`, `current_identity`.
Hardening is verified by `docs/implementation/auth-middleware-verification.md` (V-05) and
`backend/tests/architecture/test_hostile_tokens.py` (31 attacks on both surfaces).

## Scope

Replace with library options:

| ARTISEVM code | Library replacement |
|---|---|
| `BearerSchemeOnly` + the scheme rewrite | `JwtAuthMiddleware(canonical_bearer_scheme=True, error_responder=problem_responder)` (015) |
| `PathScoped` / `_ScopedJwtAuth` | `JwtAuthMiddleware(path_prefix=...)` (015) |
| `AccessTokenOidcProvider` | `OidcProviderSettings(accepted_token_types={ACCESS}, forced_jwks_refresh_min_interval_seconds=30, require_audience=True)` (016) |
| refusal of `AUTH_MIDDLEWARE_DISABLED` | `JwtAuthMiddleware(strict=True)` (016) and `Authz.install` (004) |
| `require_auth`, `current_actor`, `current_identity` | `require_authenticated()`, `get_identity()` (017) with the problem-body responder |

Keep in ARTISEVM: the problem-body builder (`infrastructure/http/problem.py`), `ALLOWED_ALGORITHMS` and
`CLOCK_SKEW_SECONDS` constants (passed as settings), the development placeholder (`rest_auth != "oidc"`:
a static bearer for local use; it is an ARTISEVM feature, not the library's).

## Acceptance criteria

- [ ] `test_hostile_tokens.py` (81 tests) passes **unchanged**; this is the proof that nothing was lost.
- [ ] `test_rest_auth.py`, `test_rest_authorization.py`, the platform tests and the integration tests that
  exercise real Cognito tokens (`make test-e2e` needs AWS; if unavailable, say so and do not claim it ran)
  pass.
- [ ] `tokens.py` shrinks to configuration and wiring (target < 60 lines); `api/auth.py` stops re-exporting
  names that no longer exist, or the exports are kept as aliases for one release if other modules import them.
- [ ] `docs/implementation/auth-middleware-verification.md` gets a note per row: "now enforced by the
  library option X; test Y proves it".
- [ ] `pyproject.toml` pins `auth-middleware>=0.7.x` (the version that has all three F issues) and `uv.lock`
  is updated with `uv lock` (backend and worker lock files).

## Out of scope

The HTMX relying party (`infrastructure/auth/oidc.py`).
