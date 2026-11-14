# AUTHZ-031 · DynamoDB policy and attribute stores

Epic H · Size L · Depends on: 029 · Blocks: 035

## Scope

`stores/dynamodb_policy.py`, `tests/authz/abac/test_dynamodb_policy_store.py`, Floci integration test,
infrastructure notes (CloudFormation/Terraform snippet) in the docs, as AUTHZ-010 did.

## Design

PynamoDB 6 models, calls in `asyncio.to_thread` (same executor/`max_workers` options and error mapping
as `DynamoDbAssignmentStore`; reuse its helper, do not copy it: extract shared code first if needed).

Separate table by default (`policy_table_name`, default `authz_policy`); the same table as assignments is
supported by choosing a distinct `sk` prefix:

| Item | `pk` | `sk` | Other attributes |
|---|---|---|---|
| Policy | `SCOPE#<kind>#<id or *>` | `POLICY#<policy_id>` | `effect`, `permissions_json`, `condition_json`, `description`, `priority`, `hide`, `enforce`, `status`, `revision`, `created_at`, `updated_at`, `gsi1pk=POLICY#<policy_id>`, `gsi1sk=POLICY` |
| Attribute | `ENTITY#<ns>#<kind>#<id>` | `ATTRS` | `attrs_json`, `revision`, timestamps |

- `list_policies(scope)` = two `Query` calls (`SCOPE#k#id`, `SCOPE#k#*`), `ConsistentRead=True`, begins_with
  `POLICY#`, paginated; merged and sorted client side. (Two small queries beat a scan; no GSI needed.)
- `get/replace/set_status` by policy id need the scope: the GSI `by-policy-id` (`gsi1pk`) resolves it
  (eventually consistent) -- **or** require the caller to pass the `PolicyScope` (decide in "Resolution";
  recommended: GSI for `get`, and `replace/set_status` re-read with the base-table key after resolving).
- Writes conditional on `revision` (`attribute_not_exists(pk)` for create). 400 KB item limit is far above
  the 16 KB policy cap; JSON stored as strings (like `attrs_json`) to avoid Decimal/float pitfalls.
- A policy's `scope` is immutable after creation (a move is delete+create) because it is part of the key.

## Acceptance criteria

- [ ] Passes the AUTHZ-029 contract suite on moto and on Floci.
- [ ] Throttling/5xx -> `StoreUnavailableError`; conditional failure -> `RevisionConflictError`.
- [ ] Guard-path reads (`list_policies`) are consistent reads; test asserts the flag is sent.
- [ ] Item for a kind-wide policy and a scope policy do not collide (same policy id in two scopes is
  allowed? **no**: ids are globally unique, enforced through the GSI conditional check or a marker item;
  record the chosen mechanism in "Resolution").
- [ ] Table creation helper + IaC notes in docs; IAM policy lists exactly the needed actions.
- [ ] Works without `boto3` extras beyond the `dynamodb` extra already defined.
