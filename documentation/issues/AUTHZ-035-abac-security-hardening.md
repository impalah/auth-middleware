# AUTHZ-035 · Security hardening battery

Epic H · Size M · Depends on: 027, 030, 031

## Context

0.7.0 had a hostile-token battery (AUTHZ-015/016) and a quality review that found fail-open bugs. ABAC
accepts attacker-influenced data (resource attributes, headers, claims) and administrator-supplied
policies; both need adversarial tests before release.

## Scope

`tests/authz/abac/test_hostile.py`, `test_failclosed.py`, `test_limits.py`, and a section appended to
`documentation/QUALITY-REPORT-*.md` style notes (new file `QUALITY-REPORT-0.8.0.md`).

## Checklist (each item is a test)

- Policy injection: JSON with `__proto__`, `$where`, huge ints, NaN, duplicate keys, 10 000-deep nesting,
  1 MB strings -> `ConditionError`/`InvalidPolicyError`, bounded time and memory.
- Attribute injection: resource loader returning wrong types, huge lists, nested depth, bytes, objects
  with `__eq__` side effects -> INDETERMINATE or rejection, never an exception reaching the client.
- Header spoofing: `X-Forwarded-For`, `X-Tenant`, custom headers feeding `env.header.*` only when
  allow-listed; case/duplicate headers.
- Fail-closed matrix: store down, provider timeout, loader exception, invalid stored policy, cache poisoned
  (wrong type) -> 503 or 403, **never** 200.
- Evaluator totality: Hypothesis (or table-driven fuzz) over random ASTs and attribute maps: `evaluate`
  never raises and `deny` with any INDETERMINATE operand denies.
- Timing/enumeration: 404 for non-member, unknown resource and `hide` denial are byte-identical in body and
  headers.
- Tenant isolation: a policy of scope A never applies to scope B; kind-wide never leaks across kinds;
  attribute namespaces `principal` and `resource` never collide.
- Logs: no attribute values, tokens or condition literals above INFO.
- Tools: ruff, mypy strict, pyright, bandit, pip-audit clean; `vulture`/`radon` no new findings above the
  0.7.0 baseline.

## Acceptance criteria

- [ ] All checklist items have tests and pass on SQLite, moto and (marker) PostgreSQL/Floci.
- [ ] Findings and fixes recorded in `documentation/QUALITY-REPORT-0.8.0.md`.
