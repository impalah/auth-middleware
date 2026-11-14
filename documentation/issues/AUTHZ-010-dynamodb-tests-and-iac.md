# AUTHZ-010 · DynamoDB tests and infrastructure notes

Epic C · Size M · Depends on: 009 · Blocks: 014 · Open question: Q2 (test double)

## Context

`DynamoDbAssignmentStore` (AUTHZ-009) needs to run against something that behaves like DynamoDB,
including conditional writes, consistent reads and a GSI.

## Decide first (write the Resolution in this file)

Test double, in order of preference unless the owner says otherwise:

1. **moto server mode** (`moto[server]`, `ThreadedMotoServer`): works with `aioboto3` through
   `endpoint_url`; no Docker; supports conditional expressions and GSIs.
2. **DynamoDB Local** container (`amazon/dynamodb-local`): closest to the real service, needs Docker.
3. An AWS emulator already used in the owner's projects. ARTISEVM uses `floci/floci` for S3; whether it
   implements DynamoDB is **not verified** here: check its docs before choosing it.

Recommended: moto for the default `make test` (no external service), DynamoDB Local in CI as an
`integration` job. Both go through `endpoint_url` read from `AUTHZ_TEST_DYNAMODB_ENDPOINT`.

## Scope

- `tests/authz/integration/test_dynamodb_store.py` (marker `integration`).
- Dev dependency `moto[server]` (and `aioboto3` in the dev group so the extra is exercised).
- `.github/workflows/tests.yml`: a DynamoDB Local service container for the integration marker.
- `pages_source/` text is written in AUTHZ-014; here a `pages_source/infrastructure/dynamodb-setup.rst`
  draft (table definition, IAM policy, billing mode) because it belongs with the infrastructure pages.

## Design

- Fixture: create the table with `DynamoDbAssignmentStore.table_definition(...)`, run the contract
  suite, drop the table.
- DynamoDB-only tests:
  1. `ConsistentRead=True` is honoured: write then read in the same test with a client that injects a
     latency into the GSI is not possible, so assert on the request parameters through a botocore event
     hook and assert behaviour on `get_assignment` right after `revoke` (must see `REVOKED`).
  2. Conditional check: two concurrent `change_role` with the same `expected_revision`: exactly one wins.
  3. Pagination: more than 1 MB of items under one scope (use 1,500 items with 1 KB `attributes`) is
     fully returned by `list_for_scope`.
  4. GSI listing returns the principal's scopes (allow a short retry loop: GSI is eventually consistent).
- IAM policy fragment for the docs (least privilege): `dynamodb:GetItem`, `PutItem`, `UpdateItem`,
  `Query` on the table ARN and on `.../index/by-principal`; **no** `Scan`, no `DeleteItem`, no
  table-level actions for the runtime role (creating the table is a deployment concern).
- Terraform snippet in the docs mirrors `table_definition()` exactly (a test compares the rendered
  JSON-ish structure with a golden dict to prevent drift).

## Acceptance criteria

- [ ] Contract suite green against moto server in `make test` (no Docker needed).
- [ ] The four DynamoDB-only tests pass.
- [ ] Integration marker green in CI against DynamoDB Local.
- [ ] The docs draft contains the table definition, the IAM fragment and the consistency caveats.
- [ ] Golden test for `table_definition()`.

## Out of scope

Production Terraform for any application.
