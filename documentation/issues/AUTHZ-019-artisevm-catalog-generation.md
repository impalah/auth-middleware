# AUTHZ-019 · ARTISEVM: catalog generation

Epic G · Size S · **Repo: artisevm** · Depends on: 018

Same ARTISEVM rules as AUTHZ-018 (uv only, small English commits with the Claude trailer, Spanish docs,
no force-push, specification folders untouched).

## Context

`backend/tools/gen_permissions.py` generates `domain/identity/permissions.py` from
`pinturilla-functional-v2/05-actores-roles-y-permisos.md` (read-only input: do not edit the spec). The
Makefile runs `uv run python tools/gen_permissions.py --check` inside `lint` so the catalog cannot drift
from the design. The generated module holds `Role`, `Permission`, `SENSITIVE`, `SCOPE` (Spanish values:
`plataforma`, `estudio`, `propio`, `empresa o enlace`) and `ROLE_PERMISSIONS`.

## Scope

`backend/tools/gen_permissions.py` and its generated output, `backend/tests/unit/test_permission_catalog.py`
(existing: keep green).

## Design

- Keep generating `Role`, `Permission`, `SENSITIVE`, `SCOPE`, `ROLE_PERMISSIONS` exactly as today (the
  frontend permission list and many imports depend on them).
- Add a generated function `build_catalog() -> PermissionCatalog` in the same module that builds the
  library catalog from those tables:
  - scope kinds: `studio` (`hide_existence=True`) and `global` (`hide_existence=False`);
  - map `SCOPE` values: `estudio` -> `studio`; `plataforma` -> `global`; `propio`,
    `empresa o enlace`, `empresa` are **not studio-membership permissions** (they belong to showroom
    principals that stay outside the library): either omit them from the library catalog or declare a
    third scope kind `showroom`, whichever keeps `Permission` -> spec 1:1. Decide, write it in
    "Resolution", and make the test assert the count (39 in the spec; N in the library catalog).
  - `sensitive` from `SENSITIVE`.
- `--check` also verifies that `build_catalog()` validates (the library raises `CatalogError` listing all
  problems).

## Acceptance criteria

- [ ] `make lint` (which includes `gen_permissions.py --check`) passes.
- [ ] A test asserts `build_catalog().permissions_for(role.value) == frozenset(p.value for p in ROLE_PERMISSIONS[role])`
  for every role.
- [ ] Changing a cell in a copy of doc 05 makes `--check` fail (the existing behaviour) and the new
  catalog test fail too.
- [ ] The frontend contract copies (`frontends/packages/api-clients/contracts`) are unchanged
  (`make openapi-check`).

## Out of scope

Editing the specification; changing role codes.
