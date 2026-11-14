# AUTHZ-007 · SQLAlchemy assignment store

Epic B · Size L · Depends on: 006 · Blocks: 008, 011

## Context

Existing SQL code (`providers/sqlalchemy/`): `SqlPermissionsProvider` reads a global table
`authz_permissions(id, username, permission)` through the `AsyncDatabase` **singleton**, configured by a
classmethod or by `AUTHZ_*` environment settings; its tests mock the session. The new store must be
**injected** (an `async_sessionmaker` or a per-request session), tenant-aware, and tested against a real
database. Do not modify the legacy provider or its table.

## Scope

`src/auth_middleware/authz/stores/sqlalchemy.py` (module name `sqlalchemy.py` inside a package named
`stores` is fine with absolute imports, but name it `sql.py` to avoid confusion with the library),
`src/auth_middleware/authz/stores/sql_models.py`, `tests/authz/test_sql_store_unit.py`.
Gated by the existing `sqlalchemy` extra; import the module lazily from `stores/__init__.py` via
`__getattr__` so that `import auth_middleware.authz` never imports sqlalchemy.

## Design

Table `authz_assignment` (own `DeclarativeBase`, **not** the legacy `Base`, so applications can include
it in their own metadata/Alembic or use ours):

| Column | Type | Notes |
|---|---|---|
| `id` | `String(27)` PK | ksuid (the library already depends on `svix-ksuid`) |
| `principal_id` | `String(500)` | the token `sub` |
| `scope_kind` | `String(50)` | |
| `scope_id` | `String(200)` | |
| `role` | `String(100)` | |
| `status` | `String(10)` | `active` / `revoked`; CHECK constraint |
| `revision` | `Integer` | starts at 0 |
| `created_at`, `updated_at` | `DateTime(timezone=True)` | server default now |
| `attributes` | `JSON` (`JSONB` on PostgreSQL) | nullable; free data |

Indexes/constraints: `UNIQUE (principal_id, scope_kind, scope_id)`; index on `(scope_kind, scope_id)`
for `list_for_scope`.

```python
class SqlAssignmentStore:  # implements AssignmentStore and AssignmentAdmin
    def __init__(
        self,
        session_provider: SessionProvider,
        *,
        table_name: str = "authz_assignment",
        before_query: Callable[[AsyncSession, ScopeRef | None], Awaitable[None]]
        | None = None,
        commit: bool = True,
    ) -> None: ...


SessionProvider = (
    async_sessionmaker[AsyncSession]
    | Callable[[], AsyncContextManager[AsyncSession]]
    | AsyncSession
)
```

- Three ways to inject a session, to cover both deployment shapes:
  1. `async_sessionmaker`: the store opens a short session per call (singleton store at startup).
  2. A callable returning an async context manager (apps with their own session helper).
  3. An **already open `AsyncSession`** (per-request store built by a `StoreFactory`): the store never
     opens, commits or closes it (`commit=False` forced), so reads happen in the **request's
     transaction**. This is the shape ARTISEVM needs.
- `before_query` runs before every statement with the session and the scope (or `None` for
  `list_assignments`, which is cross-scope). This is where an application binds RLS
  (`SELECT set_config('app.studio_id', :id, true)`). It is awaited, its exceptions propagate.
- Writes use optimistic concurrency: `UPDATE ... WHERE id=:id AND revision=:expected` and check
  `rowcount == 1`, else `RevisionConflictError`. `assign` relies on the unique constraint:
  catch `IntegrityError` -> `RevisionConflictError` (or reactivation path when a revoked row exists).
- No raw string SQL interpolation; `table_name` is only used to build the `Table` object (validate with
  `[A-Za-z_][A-Za-z0-9_]*`).
- No use of `AsyncDatabase`. Reuse nothing global.

## Acceptance criteria

- [ ] Passes `AssignmentStoreContract` (AUTHZ-006) against SQLite+aiosqlite in unit tests (fast, in CI
  without services) **and** PostgreSQL in AUTHZ-008.
- [ ] Case 11 (20 concurrent `assign`) passes on PostgreSQL.
- [ ] With an injected open session the store issues no `commit`/`rollback`/`close` (test with a spy).
- [ ] `before_query` is called before every statement (test records the order against executed SQL via
  an event listener).
- [ ] The guard test of AUTHZ-005 runs end to end with this store and a per-request session factory.
- [ ] Importing `auth_middleware.authz` without the extra works; using the store without it raises a
  clear `ImportError` naming `pip install auth-middleware[sqlalchemy]`.
- [ ] MySQL: schema creation works with `aiomysql` types (no JSONB-only features outside a dialect
  variant); full MySQL integration is best effort (documented).

## Open points to decide in the PR (write the Resolution here)

- `aiosqlite` as a dev dependency (needed for the fast unit tests). Recommended: add to the dev group.

## Out of scope

Migration files and the real-database CI job (AUTHZ-008); legacy provider changes.
