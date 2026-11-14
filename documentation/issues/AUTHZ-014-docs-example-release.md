# AUTHZ-014 · Docs, example, CHANGELOG and release `0.7.0`

Epic E · Size M · Depends on: Epics A, B, C, D complete · Open question: **Q3**

## Context

Docs are Sphinx (`pages_source/*.rst`, built into the committed `docs/` HTML by `make docs`). The README
has a stale "Package Structure" section (it lists a removed profile provider; see `CLAUDE.md`).
Version bumps go through `make bump-version PART=minor`, which keeps `pyproject.toml`,
`src/auth_middleware/__init__.py` and `pages_source/conf.py` in sync (`scripts/update_version.py`).

## Decide first

Q3: regenerate `docs/` (generated HTML, large diff) in this change, or leave it to the release
process? Default if unanswered: regenerate once, in this issue's last commit, separate from the source commit.

## Scope

- New pages in `pages_source/`, added to the toctree in `index.rst`:
  - `authz-overview.rst`: concepts (scope, assignment, role, catalog, the two failure modes), when to use
    flat RBAC (`require_groups`) versus scoped permissions, the architecture diagram of PLAN section 3.
  - `authz-catalog.rst`: building a catalog in code and from TOML; scope kinds and `hide_existence`.
  - `authz-stores.rst`: in-memory, SQLAlchemy, DynamoDB, writing your own adapter; the contract suite;
    per-request `StoreFactory` with a full example sharing the request's session (RLS binding).
  - `authz-fastapi.rst`: `Authz.build`, `install`, `require_permission`, `ScopeFromPath`, error policy,
    `x-permission`, `declared_permissions` for architecture tests, mounted sub-apps.
  - `authz-operations.rst`: `AssignmentService` hooks (last-owner example), CLI, cache caveats, audit.
  - `authz-migration.rst`: moving from `require_permissions`/`SqlPermissionsProvider` to the new model.
  - `infrastructure/dynamodb-setup.rst` (draft exists from AUTHZ-010): finalise.
- `examples/authz_example.py`: a runnable FastAPI app with the in-memory store, a two-role catalog, a
  tenant-scoped route and a global route (mirrors the quick start; keep it under 120 lines).
- README: a short "Scoped permissions" section with the quick start, and fix the stale package
  structure section.
- `CHANGELOG.txt`: a `Version 0.7.0` entry in the existing RST-like style (Features, Compatibility,
  Packaging, Docs). State clearly: additive; legacy guards and providers unchanged; new extra `dynamodb`.
- Version: `make bump-version PART=minor`.
- `CLAUDE.md`: add the new package to the architecture section (a few lines) and replace the "Plan"
  pointer added by this plan (see README of issues) with a "done" note.

## Acceptance criteria

- [ ] `make docs` builds with no warnings from the new pages (`-W` if the Makefile supports it).
- [ ] The example runs (`uv run uvicorn examples.authz_example:app`) and a scripted test of it passes
  (`tests/authz/test_example.py` imports the app and drives it with `httpx.ASGITransport`).
- [ ] Every code block in the new `.rst` pages that is meant to run is covered by a test or by the example
  (no untested snippets claiming to work).
- [ ] `make check` and `make test` green on 3.12 and 3.14; `uv build` produces sdist and wheel and a
  fresh virtualenv installs the wheel with and without each extra and imports `auth_middleware.authz`.
- [ ] Version strings agree in the three places.
- [ ] No removed or renamed public name (a test diff of `auth_middleware.__all__` against 0.6.2).
- [ ] The resolution log in `issues/README.md` lists every closed issue.

## Out of scope

Publishing to PyPI (the owner does it with `make publish`).
