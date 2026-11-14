# AUTHZ-016 · OIDC provider hardening options

Epic F · Size L · Depends on: none · Blocks: 021

## Context

ARTISEVM subclasses `OidcProvider` as `AccessTokenOidcProvider`
(`artisevm/backend/src/artisevm/infrastructure/auth/tokens.py`) and documents the gaps in
`artisevm/docs/implementation/auth-middleware-verification.md` (V-05, 81 passing tests in
`backend/tests/architecture/test_hostile_tokens.py`, 31 attacks x 2 surfaces). What the library lacks
(verified in `providers/oidc/oidc_provider.py`, 0.6.2):

| Gap | Today in the library | ARTISEVM's patch |
|---|---|---|
| Audience optional | `_verify_audience` returns `True` when no audience is configured | Settings require an audience per surface |
| Token type | Rejects `REFRESH`; accepts `ID` and `UNKNOWN` (`_detect_token_type`, `token_use_claim` default `"token_use"`) | Only `token_use == access` passes (Cognito signs ID and access tokens with the same key and issuer, so a leaked ID token would pass) |
| Unknown `kid` | `_get_hmac_key` finds no key -> `InvalidTokenException("No public key found!")`; JWKS refreshes only by the cache interval/usage counters | One forced JWKS refresh at most every 30 s, so an IdP key rotation works without restart and forged `kid`s cannot flood the IdP |
| Disabled verification | `jwt_token_verification_disabled` and the env flag `AUTH_MIDDLEWARE_DISABLED` can switch verification off | Refused at startup; flag fixed to `False` |
| `nbf` | Only validated when present | (documented, accepted) |

## Scope

`src/auth_middleware/providers/oidc/oidc_provider_settings.py`,
`src/auth_middleware/providers/oidc/oidc_provider.py`, `src/auth_middleware/jwt_auth_middleware.py`
(strict flag), `tests/providers/oidc/` new files. Additive fields with defaults equal to today's
behaviour.

## Design

New `OidcProviderSettings` fields:

```python
require_audience: bool = (
    False  # True: no audience configured -> ValueError at construction;
)
#       and _verify_audience never returns True without an expected value
accepted_token_types: frozenset[TokenType] | None = (
    None  # None = today; {TokenType.ACCESS} = ARTISEVM. UNKNOWN is rejected when set
)
forced_jwks_refresh_min_interval_seconds: float | None = (
    None  # None = today; 30.0 = ARTISEVM
)
```

Behaviour:

- `forced_jwks_refresh...`: in `_get_hmac_key`, when no key matches and the header has a `kid`, refresh the
  JWKS **once** if at least the interval passed since the last forced refresh; claim the timestamp
  **before** awaiting (concurrent requests share the single refresh: reproduce ARTISEVM's comment "claimed
  before the await"). A token without `kid` never triggers a refresh. Use an instance attribute, not a
  class attribute (ARTISEVM's class attribute is shared by every instance; per-instance is more correct
  for the library; add a test with two providers).
- `accepted_token_types`: after signature and claims validation, `if accepted and detect(...) not in accepted: return False`.
- `JwtAuthMiddleware(..., strict: bool = False)` (this file is also touched by AUTHZ-015; coordinate):
  `strict=True` raises `RuntimeError` at construction when `AUTH_MIDDLEWARE_DISABLED` is true or the
  provider settings have `jwt_token_verification_disabled=True`.

## Acceptance criteria

- [ ] All defaults leave every existing OIDC test green and behaviour identical.
- [ ] **Port the hostile-token suite**: re-create ARTISEVM's attack list as library tests using a local fake
  JWKS (see how `tests/providers/oidc/` builds keys today). Cover at least: `alg: none` (and `None`, and
  `none` with a signature), HS256 signed with the public key, HS256 with a symmetric key published in the
  JWKS, wrong issuer, wrong audience, expired, missing `exp`, `nbf` in the future, no `kid`, unknown
  `kid`, key rotation (new `kid` accepted after one forced refresh), 25 forged `kid`s causing at most one
  IdP fetch within the interval, ID token / refresh token / empty-scope token, `jku`/`x5u`/embedded `jwk`
  headers ignored, malformed segments, invalid JSON, 200 KB of claims. Parametrise instead of copying.
  (Read ARTISEVM's `test_hostile_tokens.py` for the exact cases; do not import from it.)
- [ ] With `require_audience=True` and no audience: constructor error; with an audience: a token with a
  different `aud`/`client_id` is rejected (existing behaviour) and a token with none is rejected.
- [ ] `accepted_token_types={ACCESS}`: Cognito-shaped ID and refresh tokens rejected, access accepted.
- [ ] `strict=True` refuses the disabled flag at construction.
- [ ] Docs: `pages_source/oidc_provider.rst` gets the three fields and a "hardening checklist" table
  (the table above, rewritten as recommendations).

## Out of scope

Changing defaults to the strict values (that would be a breaking change: needs a major version and an
ADR of the library; record it as a follow-up note in "Resolution").
