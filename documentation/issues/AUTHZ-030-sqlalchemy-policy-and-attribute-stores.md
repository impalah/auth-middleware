# AUTHZ-030 · SQLAlchemy policy and attribute stores + migration

Epic H · Size L · Depends on: 029 · Blocks: 035

## Scope

`stores/sql_policy.py`, extend `stores/sql_models.py`, Alembic revision (after `a3f1c9d2b7e4`),
`tests/authz/abac/test_sql_policy_store.py`, integration tests (marker `integration`, `floci`).

## Design

Tables (names configurable like `table_name`, plain identifiers only, own `metadata` shared with the
assignment one so Alembic autogenerate sees all):

`authz_policy`

| Column | Type | Notes |
|---|---|---|
| `id` | `String(100)` PK | the policy id (not a KSUID: it is human-chosen) |
| `effect` | `String(10)` | CHECK in (deny, require, permit) |
| `scope_kind` | `_ident(50)` | |
| `scope_id` | `_ident(200)` NULL | NULL = kind-wide |
| `permissions` | JSON/JSONB | list of strings |
| `condition` | JSON/JSONB | the AST |
| `description` | `String(500)` | |
| `priority` | Integer | |
| `hide`, `enforce` | Boolean | |
| `status` | `String(10)` | CHECK active/revoked-style (`active`, `disabled`) |
| `revision`, `created_at`, `updated_at` | as the assignment table | |

Index `(scope_kind, scope_id, status)`. `list_policies(scope)` is one `SELECT ... WHERE scope_kind=:k AND
(scope_id=:i OR scope_id IS NULL) AND status='active'`.

`authz_attribute`: `id` KSUID PK, `namespace` (`principal`|`resource`), `kind` (`_ident(50)`; `principal`
uses `"principal"`), `entity_id` (`_ident(500)`), `attributes` JSON/JSONB, `revision`, timestamps;
`UNIQUE(namespace, kind, entity_id)`.

Behaviour copied from `SqlAssignmentStore`: three session-injection shapes, `before_query` hook (RLS),
no commit on an injected session, duplicate-key detection (`_is_duplicate_key`), re-read before commit,
`MySQL utf8mb4_bin`, `StoreUnavailableError` on `OperationalError`/`InterfaceError`.
Do **not** touch the assignment table or its revision.

## Acceptance criteria

- [ ] Passes the full AUTHZ-029 contract suite on SQLite (aiosqlite), PostgreSQL 17 and MySQL via Floci.
- [ ] Alembic upgrade/downgrade test on SQLite and PostgreSQL; downgrade drops only the two new tables.
- [ ] JSONB on PostgreSQL, JSON elsewhere; round trip keeps ints vs floats and key order irrelevant.
- [ ] `before_query` called for every statement; exception propagates.
- [ ] Injected session: a failed insert does not poison the caller's transaction (savepoint).
- [ ] `import auth_middleware.authz.stores` without sqlalchemy still works (lazy attribute).
- [ ] Table/identifier validation rejects injection attempts in `table_name`.
