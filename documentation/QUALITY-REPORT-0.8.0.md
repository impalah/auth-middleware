# Quality report · ABAC (Epic H, 0.8.0, unreleased)

Date: 2026-11-20 · Scope: `src/auth_middleware/authz/abac/`, `stores/sql_policy.py`,
`stores/dynamodb_policy.py`, `testing/contract_abac.py`, the changes in `engine.py`, `runtime.py`,
`guards.py`, `cli.py`, `services/metrics.py`, and `alembic/versions/b7d2e5f1c3a8_authz_abac.py`.

## Tools and results

| Tool | Result |
|---|---|
| `make check` (ruff lint + format, mypy strict, bandit) | clean |
| pyright (`--pythonpath .venv/bin/python src`) | 0 errors, 0 warnings |
| pip-audit (all extras, resolved from `uv.lock`) | no known vulnerabilities |
| deptry | no dependency issues |
| vulture (>= 80 %) | one false positive in the contract suite (`tb` of a context manager) |
| radon cc | worst functions went from C(19)/C(15)/C(15)/C(12) to C(<= 12) after refactoring |
| tests | 1315 passed on the default run (was 917 at 0.7.0), 3.12/3.13/3.14 by CI |
| coverage of the new modules | 94 %-100 % (the lazy `abac/__init__` 85 %) |
| real engines | contract suites on PostgreSQL 17 (alembic upgrade/downgrade included), and on DynamoDB, PostgreSQL and MySQL through Floci (`make test-floci`, 103 tests) |
| mutation check | weakening "a deny applies when INDETERMINATE" makes 6 tests fail (the battery is not vacuous) |

## Findings and what was done

| # | Finding | Found by | Fix |
|---|---|---|---|
| 1 | **Race in DynamoDB policy-id uniqueness.** A loser of a concurrent `create` saw the winner's id marker before its policy item existed, took it for a crash leftover and "recovered" it: two scopes could end up with the same policy id. moto's timing hid it. | Floci (contract case "concurrent create has one winner") | Recovery only for markers older than 30 s and with a compare-and-set on `created_at`; tests for young and old markers |
| 2 | A poisoned cache entry (wrong type) or a source returning odd objects raised `AttributeError` outside the guarded block: a 500 instead of a controlled outage. | Hostile battery | The decision point wraps every unexpected error as `StoreUnavailableError` (503) |
| 3 | A static `deny` reading `env.header.x` or `subject.claims.x` that nobody allow-listed is always INDETERMINATE and therefore denies **every** request: a silent total outage. | Review of the fail-closed semantics | `AbacConfig.build` rejects it at startup, naming the policy and the attribute |
| 4 | `bool` vs number: the issue text said `eq(true, 1)` is FALSE, which lets a `deny` silently miss (`deny if flag == true` with `flag = 1`). | Design review | Any type mismatch is INDETERMINATE (stricter than the issue text; recorded in the resolution log) |
| 5 | Four `assert` statements used to narrow types (bandit B101). | bandit | Explicit checks |
| 6 | The first policy file of the example named the role `SUP` while the catalog's role is `SUPPORT`: the policy never matched. | The example's own test | Fixed; this is why the cookbook is a validated fixture |
| 7 | The old migration test downgraded `-1` and expected the assignment table to be gone. | Postgres run | Test updated: the ABAC revision drops only its own tables |

## Properties verified by tests

* `restrict` mode never turns a denial into an allow (property test over random policies).
* A `deny` applies exactly when its condition is not FALSE (300 random conditions x random values, including
  hostile types).
* `evaluate` never raises (3000 random conditions); hostile `__eq__` objects are never called; `str`
  subclasses are copied to exact `str`.
* Every "not visible" answer (non-member, unknown resource, `hide` denial, unknown scope, oversized id) is
  byte-identical in status, body and headers.
* Policies never cross scopes or scope kinds; principal and resource attributes never collide.
* Logs, events and exceptions never contain attribute values.
* Hostile policy documents (10^400 integers, 1 MB strings, 50 000-deep nesting, `$where`, path traversal in
  attribute paths) are rejected in well under half a second.

## Known limits (documented)

* Other processes see a policy change only after the cache TTL (5 s by default).
* `grant` mode is experimental.
* `list_all` on DynamoDB is a `Scan` (tooling only, never the request path).
* A policy of the global scope is stored under `*` in DynamoDB whether it was created as
  `PolicyScope("global")` or `PolicyScope("global", "*")`.
* No list filtering (partial evaluation), obligations or HTTP management API.
