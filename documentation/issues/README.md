# Issues · scoped permissions (see `../PLAN-authz.md`)

One file per issue, written to be executed by Claude Code (or a person) without further context.
Read `../PLAN-authz.md` first (design, vocabulary, decisions) and `../../CLAUDE.md` (commands, style).

## Index and execution order

Legend: size S (< 1 h), M (half a day), L (a day or more). "Repo" says where the work happens.

| Id | Title | Epic | Size | Repo | Depends on |
|---|---|---|---|---|---|
| [AUTHZ-001](AUTHZ-001-domain-model-and-ports.md) | Domain model, errors and ports | A | M | auth-middleware | none |
| [AUTHZ-002](AUTHZ-002-permission-catalog.md) | Permission catalog and role matrix | A | M | auth-middleware | 001 |
| [AUTHZ-003](AUTHZ-003-authorizer-engine.md) | Authorizer engine and role resolvers | A | M | auth-middleware | 001, 002 |
| [AUTHZ-004](AUTHZ-004-authz-runtime-and-di.md) | `Authz` runtime and startup injection | A | M | auth-middleware | 003 |
| [AUTHZ-005](AUTHZ-005-fastapi-guard.md) | FastAPI guard `require_permission` | A | L | auth-middleware | 004 |
| [AUTHZ-006](AUTHZ-006-memory-store-and-contract-suite.md) | In-memory store and store contract suite | A | M | auth-middleware | 001 |
| [AUTHZ-007](AUTHZ-007-sqlalchemy-store.md) | SQLAlchemy assignment store | B | L | auth-middleware | 006 |
| [AUTHZ-008](AUTHZ-008-sqlalchemy-migration-and-integration-tests.md) | Alembic migration and real-database tests | B | M | auth-middleware | 007 |
| [AUTHZ-009](AUTHZ-009-dynamodb-store.md) | DynamoDB assignment store | C | L | auth-middleware | 006 |
| [AUTHZ-010](AUTHZ-010-dynamodb-tests-and-iac.md) | DynamoDB tests and infrastructure notes | C | M | auth-middleware | 009 |
| [AUTHZ-011](AUTHZ-011-assignment-service-and-cli.md) | Assignment service and `authcli` commands | D | M | auth-middleware | 007 or 009 |
| [AUTHZ-012](AUTHZ-012-optional-cache.md) | Optional short-lived cache | D | S | auth-middleware | 004; open question Q1 |
| [AUTHZ-013](AUTHZ-013-audit-and-metrics.md) | Audit events and metrics | D | S | auth-middleware | 004 |
| [AUTHZ-014](AUTHZ-014-docs-example-release.md) | Docs, example, CHANGELOG, `0.7.0` | E | M | auth-middleware | A, B, C, D done |
| [AUTHZ-015](AUTHZ-015-middleware-bearer-and-prefix-options.md) | Middleware options: canonical Bearer, path prefix, error responder | F | M | auth-middleware | none |
| [AUTHZ-016](AUTHZ-016-oidc-hardening-options.md) | OIDC provider hardening options | F | L | auth-middleware | none |
| [AUTHZ-017](AUTHZ-017-authenticated-guard-and-identity.md) | `require_authenticated` and `get_identity` | F | S | auth-middleware | 015 |
| [AUTHZ-018](AUTHZ-018-artisevm-adapter-and-parity.md) | ARTISEVM: store adapter, wiring and parity tests | G | L | artisevm | 0.7.0 released; Q4 approved |
| [AUTHZ-019](AUTHZ-019-artisevm-catalog-generation.md) | ARTISEVM: catalog generation | G | S | artisevm | 018 |
| [AUTHZ-020](AUTHZ-020-artisevm-swap-guards.md) | ARTISEVM: swap the guards, platform admin as a role | G | M | artisevm | 018, 019 |
| [AUTHZ-021](AUTHZ-021-artisevm-remove-token-duplicates.md) | ARTISEVM: drop `tokens.py` duplicates | G | M | artisevm | 015, 016, 017, 020 |
| [AUTHZ-022](AUTHZ-022-decision-memberships-into-library-tables.md) | Decision record: memberships into library tables | G | S | both | 020 |

Suggested order: 001 -> 002 -> 003 -> 004 -> 005, with 006 in parallel from 001; then B and C
(independent, can run in parallel); then 011, 012, 013; then 014 (release `0.7.0`). Epic F is independent
and can ship earlier as `0.7.x`. Epic G starts after the release.

## Definition of done (applies to every `auth-middleware` issue)

- [ ] `make check` passes (ruff lint, ruff format, mypy strict on `src/`, bandit).
- [ ] `make test` passes; new code has tests; coverage of the new modules >= 90 %.
- [ ] Async tests carry `@pytest.mark.asyncio` (there is no global asyncio mode).
- [ ] Python 3.12 compatibility: `from __future__ import annotations` in every new module; nothing
  that only exists in 3.13/3.14.
- [ ] No existing public name of 0.6.2 changes behaviour or disappears.
- [ ] Public classes and functions have Google-style docstrings with `Args:`/`Returns:`/`Raises:`.
- [ ] Optional dependencies are imported lazily or behind the extra; `import auth_middleware` still
  works with no extra installed (a test proves it).
- [ ] The issue's own acceptance checklist is ticked in the pull request description.
- [ ] Docs: the issue says which `pages_source/` page it touches; `docs/` (generated HTML) is only
  regenerated in AUTHZ-014 (see Q3 in the plan).

## Conventions

- Small commits, imperative message, English. Do not push. Do not bump the version (AUTHZ-014 does,
  through `make bump-version PART=minor`). Never edit `docs/` by hand.
- New code lives under `src/auth_middleware/authz/`; tests mirror it under `tests/authz/`.
- Naming: ports are `Protocol`s, concrete stores end in `Store`, errors end in `Error`.
- When an issue says "decide", record the decision in the issue's "Resolution" section before coding.
- If something in an issue contradicts the code you find, stop and update the issue first (the plan
  was written from a read of 0.6.2, 2026-11-14).

## Resolution log

(Add one line per closed issue: id, date, commit range, deviations from the issue.)
- AUTHZ-001..006 · 2026-11-14 · one commit (Epic A). Deviations: `NewAssignment` gained an optional
  `attributes` field (contract case 10 needs to set attributes at `assign`); `DecisionEvent` is defined in
  `runtime.py` (AUTHZ-013 fills in emission); ruff per-file-ignore B008/E501 for `tests/authz/*`.
- AUTHZ-007, 008 · 2026-11-14 · Epic B. `aiosqlite` added to the dev group. Deviations: `alembic/env.py`
  imported a module that no longer exists (`providers.authz.sql_base_model`); fixed to
  `providers.sqlalchemy.sql_base_model`, also includes the authz metadata and accepts
  `config.attributes["connection"]`. Integration tests run inside a throwaway schema (not the public one).
  Verified against postgres:17 locally (15 passed); MySQL not exercised.
- AUTHZ-009, 010 · 2026-11-14 · Epic C, **using PynamoDB 6 (owner's request) instead of aioboto3**: the extra
  is `dynamodb = ["pynamodb>=6.0"]`; PynamoDB is synchronous so every call runs in `asyncio.to_thread`.
  Constructor takes `region`/`endpoint_url`/retry+timeout settings instead of `session`/`client_factory`.
  `attributes` is stored as a JSON string (`attrs_json`, <= 4 KB) rather than a map `M`; items also carry
  `principal_id`, `scope_kind`, `scope_id` (no key parsing). Q2 resolved with the recommended default: tests
  run on `moto` server (dev dep) and the same module runs on DynamoDB Local when
  `AUTHZ_TEST_DYNAMODB_ENDPOINT` is set (CI job `integration-dynamodb`, not yet run in CI). Added
  `StoreUnavailableError`. Side effects: bandit excludes `authz/testing` (assert-based contract suite,
  makefile); `tests/providers/aws/test_cognito_auth_service.py` fake error now subclasses botocore's
  `ClientError` when botocore is installed (it broke as soon as botocore arrived via the new dependencies).
- AUTHZ-011, 013 · 2026-11-14 · Epic D (part). `authcli authz assign|revoke|list` takes an optional `--catalog`;
  `UnknownRoleError` is also a `ValueError`. `DecisionEvent` reshaped to the issue's fields (`kind`, `sensitive`,
  `duration_ms`, `request_id`); `MetricsCollector` got the additive `record_authz_decision`/`get_authz_metrics`
  (the existing snapshot is untouched); `AuditLogger` is reused (level chosen per decision).
- AUTHZ-012 · 2026-11-14 · opt-in `CachingAssignmentStore` (never wrapped by `Authz.build`). Q1 not answered by the owner:
  implemented as the issue allows (other adopters); ARTISEVM must keep it off until Q1 is decided.
  `tests/commands/test_cli.py::test_cli_group_no_commands_by_default` asserted exactly one command; now expects
  `{"get-permissions", "authz"}` (the legacy command tests are untouched).
- AUTHZ-014 · 2026-11-14 · Epic E. Docs pages, example (100 lines, tested), README, CHANGELOG, CLAUDE.md, version 0.7.0.
  `make bump-version` also rewrote `svix-ksuid>=0.6.2` to `>=0.7.0` (string match); reverted by hand. Sphinx `-W` is not
  usable (many pre-existing warnings in older pages); the new pages build with none. Q3: default applied, `docs/`
  regenerated in its own commit. Verified: py3.14 and 3.12 suites, mypy, wheel installs with/without each extra.
- AUTHZ-015, 017 · 2026-11-14 · Epic F (part), no version bump (ship as 0.7.x). `AuthFailure` lives in `jwt_auth_middleware.py`.
  Options touch the request only when enabled (the existing middleware tests use mocked requests). Pure-ASGI variant
  (`JwtAuthASGIMiddleware`) NOT implemented, per the issue; pros: no `BaseHTTPMiddleware` response buffering / contextvar
  loss, streaming safe, one less layer; cons: a second code path to keep in sync, header rewriting and error responses
  must be done by hand on raw ASGI messages, and existing subclasses of `JwtAuthMiddleware` would not carry over.
  Recommended only if an adopter hits streaming/contextvar problems. `get_identity`/`require_authenticated` documented in
  `pages_source/functions.rst`; middleware options in `middleware-configuration.rst` (the older `include_paths`/`exclude_paths`
  rows there describe parameters that do not exist in the code; left untouched).
- Post-release (2026-11-14) · layout and tooling: `docs/`->`pages/`, `docs_source/`->`pages_source/`, project docs in `docs/`;
  dependencies at latest stable (svix-ksuid 0.7.0 is real); Sphinx builds with `-W`. Floci + testcontainers tests added for
  DynamoDB, PostgreSQL (asyncpg) and MySQL (aiomysql), all 40 green. They found a real bug: on MySQL identifiers were compared
  case-insensitively; fixed with `utf8mb4_bin` and a new contract case (`test_ids_are_case_and_accent_sensitive`).
- AUTHZ-016 · 2026-11-14 · Epic F done. Forced refresh overrides `_get_hmac_key` in `OidcProvider` only (not the shared contract),
  per-instance state, and concurrent requests *await the same in-flight refresh* (they succeed) instead of being refused. The
  hostile battery (31 cases) runs through `JwtAuthMiddleware`; ARTISEVM's "200 KB of claims -> 401" is NOT reproduced: a
  validly signed oversized token is accepted by the library (no size cap), the test only asserts no 500; a 200 KB garbage
  token is 401. Defaults not changed (would be breaking: follow-up for a major version + ADR). CHANGELOG has an
  "Unreleased (0.7.x)" entry; the version bump is left to the owner.
