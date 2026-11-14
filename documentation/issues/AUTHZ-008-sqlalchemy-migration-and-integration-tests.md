# AUTHZ-008 · Alembic migration and real-database tests

Epic B · Size M · Depends on: 007 · Blocks: 014

## Context

The repository has `alembic/` with one migration creating the legacy `authz_permissions` table
(`alembic/versions/de961fac6f27_initial_migration.py`), and dev dependencies `alembic` and
`psycopg2-binary`. No test runs against a real database today (`tests/providers/sqlalchemy/*` mock the
session). `.github/workflows/tests.yml` exists.

## Scope

- `alembic/versions/<new>_authz_assignment.py` creating `authz_assignment` (revises `de961fac6f27`),
  with `downgrade`.
- `tests/authz/integration/test_sql_store_postgres.py` (marker `integration`).
- `pyproject.toml`: pytest marker `integration`; dev dependency group addition if needed.
- `.github/workflows/tests.yml`: a PostgreSQL service job.
- `pages_source/` page text is written in AUTHZ-014; here only a README paragraph under `alembic/`.

## Design

- The migration is written by hand from the model of AUTHZ-007 (do not rely on autogenerate output
  without reading it). Add the CHECK on `status`, the UNIQUE and the index.
- A second path for applications that own their migrations: export
  `auth_middleware.authz.stores.sql_models.metadata` and document `target_metadata` inclusion.
- Integration tests read the URL from `AUTHZ_TEST_POSTGRES_URL` and **skip** when it is not set. Locally:
  `docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:17` and
  `AUTHZ_TEST_POSTGRES_URL=postgresql+asyncpg://postgres:pw@localhost:5432/postgres`.
- Fixture creates a fresh schema per test module (create tables from metadata), runs the contract suite,
  then adds the PostgreSQL-only tests below.

PostgreSQL-only tests:

1. **RLS door**: create a role without BYPASSRLS, enable a policy on `authz_assignment` using
   `current_setting('app.scope_id', true)`, use `before_query` to bind it, and prove that without
   binding the store sees no row and with the right binding sees only that scope (this is the property
   ARTISEVM relies on; its own implementation: `artisevm/backend/src/artisevm/infrastructure/db/rls.py`).
2. **Per-request transaction**: an injected `AsyncSession` inside `session.begin()`; a write by the store
   is rolled back when the caller rolls back (proves no hidden commit).
3. **Migration round trip**: `alembic upgrade head` then `downgrade -1` leaves the legacy table intact.

## Acceptance criteria

- [ ] `uv run pytest -m integration` passes with a PostgreSQL available; without it the tests skip
  (not fail) and say why.
- [ ] Contract suite green on PostgreSQL, including the concurrency case.
- [ ] CI runs the integration marker against a `postgres:17` service container (pin the major version).
- [ ] Migration applies on an empty database and on one that already has `authz_permissions`.
- [ ] The three PostgreSQL-only tests exist and pass.

## Out of scope

MySQL CI (documented as untested in CI), DynamoDB (009/010).
