# AUTHZ-009 · DynamoDB assignment store

Epic C · Size L · Depends on: 006 · Blocks: 010, 011

## Context

Today there is **no DynamoDB code** in the library: `pages_source/extending-authz-providers.rst` (line
~280) only shows a sample `DynamoDBGroupsProvider` using synchronous `boto3`, and `pyproject.toml` has
no AWS dependency (`providers/aws/services/cognito_auth_service.py` imports `boto3` lazily). The new
store must be async, injected at startup, and must satisfy the same contract as the SQL store.

## Scope

`src/auth_middleware/authz/stores/dynamodb.py`, `tests/authz/test_dynamodb_store_unit.py`,
`pyproject.toml` extra:

```toml
dynamodb = ["aioboto3>=13"]   # pin a tested lower bound; verify the latest version when implementing
```

Lazy import through `stores/__init__.py::__getattr__`; clear `ImportError` naming the extra.

## Design

Single table, on-demand billing recommended. Key design (write it in the module docstring):

| Attribute | Value | Purpose |
|---|---|---|
| `pk` (S, HASH) | `SCOPE#<kind>#<id>` | one partition per scope |
| `sk` (S, RANGE) | `PRINCIPAL#<principal_id>` | one item per (scope, principal) |
| `gsi1pk` (S) | `PRINCIPAL#<principal_id>` | GSI `by-principal`, HASH |
| `gsi1sk` (S) | `SCOPE#<kind>#<id>` | GSI `by-principal`, RANGE |
| `role`, `status`, `revision` (N), `created_at`, `updated_at`, `attributes` (M) | | payload |

Access paths:

- `get_assignment` -> `GetItem(pk, sk, ConsistentRead=True)`. **Consistent read is the default and is
  required for the guard path**: an eventually consistent read could admit a just-revoked principal.
  Expose `consistent_read: bool = True` for the rare caller who accepts staleness, documented as such.
- `list_for_scope` -> `Query(pk=..., begins_with(sk, 'PRINCIPAL#'))`, paginated until exhausted.
- `list_assignments(principal)` -> `Query` on the GSI. GSIs only support **eventually consistent**
  reads: document that "my scopes" listings may lag by a moment and that the guard never uses it.
- Writes use **conditional expressions**: `assign` -> `PutItem` with
  `attribute_not_exists(pk)` (or, when a revoked item exists, `status = :revoked` and a reactivation
  `UpdateItem`); `change_role`/`revoke` -> `UpdateItem` with `ConditionExpression: revision = :expected`
  and `SET revision = revision + :one`. `ConditionalCheckFailedException` -> `RevisionConflictError`.
- Ids containing `#` are rejected at write time (`ValueError`) so keys stay unambiguous.
- Injection:

```python
class DynamoDbAssignmentStore:
    def __init__(
        self,
        *,
        table_name: str,
        session: aioboto3.Session | None = None,  # injected; default built lazily
        client_factory: Callable[[], AsyncContextManager[Any]]
        | None = None,  # tests / custom endpoints
        index_name: str = "by-principal",
        consistent_read: bool = True,
    ) -> None: ...
    async def aclose(self) -> None: ...  # closes the client it opened
    @staticmethod
    def table_definition(
        table_name: str, *, billing: Literal["PAY_PER_REQUEST"] = ...
    ) -> dict[str, Any]: ...
    async def create_table_if_missing(
        self,
    ) -> None: ...  # dev/tests only; never called implicitly
```

- Retries/throttling: rely on botocore's retry config (document `Config(retries={"mode": "adaptive"})`);
  map `ProvisionedThroughputExceededException` after retries to a library `StoreUnavailableError`
  (add it to `errors.py` in this issue) so the guard can answer 503 through the error policy rather than 500.
- No credentials in code or logs; never log item contents above debug.

## Acceptance criteria

- [ ] Unit tests with a fake client (no network) cover: key construction, conditional writes mapping,
  pagination, `#` rejection, error mapping.
- [ ] `table_definition()` output is valid input for `create_table` (validated in AUTHZ-010).
- [ ] The store passes `AssignmentStoreContract` in AUTHZ-010 (this issue only needs the unit tests
  green plus the contract wired and skipped when no endpoint is configured).
- [ ] `import auth_middleware.authz` works without `aioboto3`.
- [ ] Consistent-read default is covered by a test asserting `ConsistentRead=True` is sent.

## Open points (write the Resolution here)

- Item `attributes` size: DynamoDB items cap at 400 KB; document a small limit (e.g. 4 KB) and enforce
  it with a clear error.

## Out of scope

IaC (Terraform) beyond the documented table definition (010); caching (012).
