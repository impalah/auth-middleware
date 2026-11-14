# AUTHZ-032 · `PolicyService`, static policy files and `authcli authz policy`

Epic H · Size M · Depends on: 025, 029 · Blocks: 036

## Scope

`abac/service.py`, `abac/static.py`, `cli.py` (new `policy` group under `authz`), `tests/authz/abac/test_policy_service.py`,
`tests/test_cli_policy.py`.

## Design

- `PolicyService(admin: PolicyAdmin, catalog, *, allow_permit=False, after_change=None)`: validates with
  `validate_policy` (025) **before** writing; per-policy-id `asyncio.Lock` like `AssignmentService`;
  `after_change(event)` callback (used by the cache in 033 and for audit).
- `StaticPolicySource.from_file(path)` / `from_policies([...])`: TOML/JSON, validated at load, read-only;
  `CompositePolicySource(static, store)`: ids must not clash (`ConfigurationError`), static first.
- CLI (reuses `_build_store`; new env `AUTHZ_POLICY_TABLE`, SQL uses the same URI):
  - `authcli authz policy add --store S --file policy.json --catalog catalog.toml`
  - `list [--scope KIND:ID] [--all]`, `show ID`
  - `disable ID --expected-revision N`, `enable ID --expected-revision N`, `replace ID --file ... --expected-revision N`
  - `validate --file policy.json --catalog catalog.toml` (offline, no store)
  - `test --file policy.json --catalog catalog.toml --context ctx.json` evaluates a policy against a JSON
    context (`{"subject": {...}, "resource": {...}, "env": {...}, "permission": "..."}`) and prints the
    three-valued result and the effect it would have. **No store needed**: the dry-run tool for writing
    policies safely.
- `--catalog` is mandatory for `add/replace` (no `--no-validate` escape hatch: a policy is code).

## Acceptance criteria

- [ ] Service rejects invalid policies with all errors listed; does not call the store when invalid.
- [ ] Concurrent `replace` of the same id: one wins, the other gets `RevisionConflictError`.
- [ ] CLI round trips on SQLite and DynamoDB (moto); exit codes: 0 ok, 1 domain error, 2 usage.
- [ ] `policy test` covers TRUE / FALSE / INDETERMINATE and prints which attribute was absent.
- [ ] Static + store id clash fails at build.
- [ ] `authcli` still imports without sqlalchemy/pynamodb (existing subprocess test extended).
