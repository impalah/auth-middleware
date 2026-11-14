# AUTHZ-029 · In-memory policy/attribute stores and contract suite

Epic H · Size M · Depends on: 023 · Blocks: 030, 031, 032, 033

## Context

Same approach as AUTHZ-006: the memory store defines the behaviour, a reusable contract suite makes the SQL
and DynamoDB stores prove they match it.

## Scope

`stores/memory.py` (add `MemoryPolicyStore`, `MemoryAttributeStore`),
`testing/contract_abac.py` (public, like `testing/contract.py`), `tests/authz/abac/test_memory_stores.py`.

## Design

Contract cases (each is a function taking a store factory; document how to run them against a new store):

1. `create` + `get` round trip, including `condition`, `permissions`, `hide`, `enforce`, `priority`.
2. Duplicate id -> `PolicyConflictError`.
3. `list_policies(scope)` returns scope-specific **and** kind-wide active policies, not other scopes or
   kinds, not disabled ones, ordered by `(priority, id)`.
4. `replace` with stale `expected_revision` -> `RevisionConflictError`; success bumps revision by 1.
5. `set_status(disabled)` hides it from `list_policies` but `get`/`list_all` still show it (history).
6. Unknown id: `get` -> `None`; `replace/set_status` -> `RevisionConflictError` (not "not found": same
   answer as stale, nothing to probe).
7. Concurrency: 20 concurrent `replace` with the same expected revision -> exactly one wins.
8. Attributes: `put` (create with `expected_revision=None`), update with revision, stale -> conflict,
   `delete`, `get` of unknown -> `None`; principal and resource namespaces do not collide for the same id.
9. Size limits: attributes > 4 KB and policy documents > 16 KB rejected with `InvalidPolicyError`.
10. Unicode/case: ids and attribute keys are case-sensitive exact (`Abc` != `abc`).
11. Store outage (fault-injecting wrapper) -> `StoreUnavailableError`.

## Acceptance criteria

- [ ] Memory stores pass all cases; the suite is importable from `auth_middleware.authz.testing`.
- [ ] A deliberately wrong store (fixture) fails the relevant cases (suite is not vacuous).
- [ ] Documented in the extending-stores page.
