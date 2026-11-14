# Quality review of auth-middleware 0.7.0

Date: 2026-11-14 · Scope: whole `src/` (legacy code + the new `auth_middleware.authz`), packaging, CI and docs.
Status: all findings remediated in 0.7.0 (round 1: sections 2; round 2: section 3).

## 1. Method

| Layer | Tool / activity | Result |
|---|---|---|
| Lint, bugs, style | `ruff` with the project rules, then `--select ALL` (statistics), then targeted `S,ASYNC,PLE,RUF,B,BLE,PERF,SIM,RET,TRY,G,PTH,...` | ~375 style hits at `ALL` (mostly docstring/exception-message conventions); 13 relevant after triage; see section 3 |
| Types | `mypy --strict` (src), `pyright` | mypy clean; pyright: 8 real-ish findings (Optional narrowing, `object.headers`) fixed |
| Security (static) | `bandit` (all severities), `ruff S` rules | no Medium/High; Low = asserts of the shipped contract suite (excluded on purpose); hardcoded-"password" false positives pinned |
| Dependencies | `pip-audit` on the exported lock (all extras, dev) | no known vulnerabilities, before and after the upgrades |
| Dependency hygiene | `deptry` | found: `boto3`/`botocore` used without an extra, `starlette` and `email-validator` imported but undeclared |
| Dead code / complexity | `vulture`, `radon cc` | vulture: only public API and framework hooks (no dead code worth removing); 5 functions at complexity C (11-13), none above |
| Coverage | `pytest --cov` | 94 % -> 95 % total; new code >= 90 % |
| Independent review | Two fresh-context reviewers (legacy security surface; new authz code), findings re-verified before acting | 26 + 22 findings, see sections 2-3 |
| Real engines | Floci + testcontainers (DynamoDB, PostgreSQL 17, MySQL 8), local PostgreSQL 17 | 40 + 16 integration tests green after the fixes |
| Not obtainable | `semgrep` (registry rules) | the scan did not complete in this environment (no output within the time limit); covered by bandit + ruff S + manual review instead |

## 2. Findings and remediation

Severity is the reviewer's estimate after verification against the code. "Verified" = reproduced or read directly in this review.

### Security / correctness (all fixed, each with a regression test)

| # | Sev | Finding | Fix |
|---|---|---|---|
| 1 | High | Basic auth logged the clear `(username, password)` at DEBUG (verified) | line removed; test captures the log |
| 2 | High | `OidcProvider` built `User(token=str(JWTAuthorizationCredentials))`: lazy `permissions/groups/roles` looked up a pydantic repr (never matched; signature logged) (verified) | token is the raw JWT; lazy providers get the parsed credentials |
| 3 | High | Entra ID: no tenant (`tid`) pin; keys are shared by all tenants; audience optional | `tid` pinned unless multi-tenant alias; warning without audience; `use` optional |
| 4 | Med | Guards passed when a provider returned `None` (verified) | `None` denies (an existing test had encoded the fail-open; changed) |
| 5 | Med | Basic auth: unknown user 401 fast vs wrong password 403 after PBKDF2 (enumeration); PBKDF2 blocked the loop; malformed header -> 500 | same work and 401 for both; `asyncio.to_thread`; malformed -> 401 |
| 6 | Med | JWKS cache: no lock (stampede), no stale fallback when the IdP is down | lock + double check, stale keys with 30 s back-off |
| 7 | Med | `RateLimiter` leaked a key per identifier and 500'd for anonymous requests; `AuditMiddleware` 500'd for anonymous; `MetricsCollector` unbounded | sweep + no empty keys; `getattr(..., None)`; bounded deque |
| 8 | Med | loguru `diagnose=True` leaks local variables (tokens/passwords) into logs; DB URL with password logged | `diagnose` off by default (`LOG_DIAGNOSE`); URL masked |
| 9 | Med | `azp`/`client_id` accepted as audience even when `aud` named another API | only as fallback for a missing `aud` |
| 10 | Med | `JsonCredentialsRepository` ignored `groups` (`_groups=` kwarg) (verified) | `groups=` |
| 11 | Low | `verify_password` raised on corrupt hashes (0/negative/huge iterations, non-ASCII) | clean `False`, iteration cap |
| 12 | Low | `User` lazy tasks cancelled with the first waiter | `asyncio.shield` |
| 13 | Low | `AUTH_MIDDLEWARE_DISABLED` silently disables everything | loud warning at middleware start (`strict=True` already refuses) |
| 14 | Med | authz: stored role missing from the catalog -> 500 for that principal (verified) | unknown roles grant nothing; warning |
| 15 | Med | authz: scope ids from the path that fail `ScopeRef` (201 chars, `*`) -> 500, distinguishable from 404 (verified) | `InvalidScopeError` -> same 404 as unknown scope |
| 16 | Med | `CachingAssignmentStore`: a read racing an invalidation re-cached the pre-revocation value (verified) | generation counter |
| 17 | Med | CLI `authz assign` wrote unvalidated roles by default | `--catalog` or explicit `--no-validate` |
| 18 | Med | `StoreUnavailableError` never became a response; DynamoDB connection/server errors not mapped | `ErrorPolicy.unavailable` (503 + Retry-After); more codes + `PynamoDBConnectionError` |
| 19 | Low | `commit=False` with an owned SQL session silently discarded writes; any `IntegrityError` was a "revision conflict" | refused; only duplicate keys conflict |
| 20 | Low | empty/oversized `sub` reached the store; `path_prefix` without `/` authenticated nothing; failing `error_responder` crashed; forced-refresh task bound to a dead loop; `forced_jwks_refresh_min_interval_seconds=0` allowed; sync `aclose` in the cache; memory-store attributes shareable; `after_change` hooks skipped after a failure; DynamoDB `#` restriction (unneeded, write-only) | each fixed |
| 21 | Low | packaging: `boto3` used without an extra; `starlette`/`email-validator` undeclared; SQLAlchemy 2.1 changed the default `postgresql://` driver (broke `alembic.ini` and a test) | `cognito` extra; deps declared; explicit `+psycopg2` |

### Tooling hardening
`ruff` now also enforces `S` (bandit rules), `ASYNC`, `PLE`, `RUF100`, `RUF012` (with narrow, commented per-file ignores);
pytest-asyncio loop scope is explicit; bandit keeps excluding only the assert-based contract suite.

## 3. Second round: items first deferred, now resolved

The first remediation left a list of "accepted / deferred" items. All of them were then fixed (with regression tests):

| Item | Resolution |
|---|---|
| OIDC defaults (audience optional, any token type) | `require_audience=True` by default (explicit opt-out + warning); warnings for `accepted_token_types=None` and disabled verification. Token types stay opt-in: the heuristic would reject some IdPs' access tokens that carry an e-mail claim |
| Cognito scope -> group/role mapping | explicit `resource_server=` / `scope_map=`; nothing is mapped by default |
| `forgot_password` / `reset_password` enumeration | generic answers |
| `require_permissions` was any-of only | `match="any"|"all"` on the three guards |
| `id_claim` default and editable claims | warning for editable claims, docs recommend `sub` |
| IdP outages answered 401 | `IdentityProviderUnavailableException` -> 503 + `Retry-After`; stale keys already served |
| veto hooks check-then-act | per-scope lock in `AssignmentService` (in-process) + explicit multi-process warning |
| DynamoDB shared executor | optional dedicated pool (`max_workers`) |
| SQL re-read after commit | re-read inside the transaction |
| sync boto3 in async code | `AsyncCognitoAuthService` |
| complexity C functions | refactored; no function above B remains |
| pyright (1 error, 5 warnings) | 0 errors, 0 warnings |
| deptry noise / undeclared deps | configured; `make deps-check` is clean |
| also from the reviews | Entra user without token/providers and dead cache settings; validation errors and a missing `sub` -> 401; unreachable "synthetic user" fallback removed; `JWTProvider.aclose()`; separate `AUTHZ_ECHO`; `needs_rehash()` upgrade path for legacy hashes |

Still true by design (not defects): the legacy SHA-256 hash format is *accepted* (use `needs_rehash` to migrate); `any`-of
remains the default for the guards; multi-process invariants must be enforced in the store.

## 4. Result

| Check | Before | After |
|---|---|---|
| `make check` (ruff, format, mypy strict, bandit) | green | green, with stricter ruff rules |
| Tests (default run) | 843 | 917 (+74 regression tests) |
| Floci (DynamoDB/PostgreSQL/MySQL) | 40 | 40 |
| Coverage | 94 % | 95 % |
| `pip-audit` | clean | clean |
| `pyright` | 5 errors, 5 warnings | 0 / 0 |
| `radon` (complexity C) | 5 functions | 0 |
| `deptry` | 14 issues | 0 |
