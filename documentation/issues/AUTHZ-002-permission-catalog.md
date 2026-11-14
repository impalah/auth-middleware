# AUTHZ-002 · Permission catalog and role matrix

Epic A · Size M · Depends on: 001 · Blocks: 003

## Context

ARTISEVM's catalog (`artisevm/backend/src/artisevm/domain/identity/permissions.py`) is a generated
module with: a `Permission` StrEnum (39 values like `design.write`), a `Role` StrEnum (`PLA`, `TIT`,
`EDI`, `LEC`, `EMP`, `INV`), `ROLE_PERMISSIONS: dict[Role, frozenset[Permission]]`, `SENSITIVE`, and
`SCOPE` (per permission: `plataforma`, `estudio`, `propio`, `empresa o enlace`). The library must offer
the *container* for such a catalog, validated, without knowing its content.

## Scope

`src/auth_middleware/authz/catalog.py`, `tests/authz/test_catalog.py`.

## Design

```python
@dataclass(frozen=True, slots=True)
class ScopeKind:
    name: str  # "studio", "global"
    hide_existence: bool = (
        True  # True: no assignment -> NOT_VISIBLE (404); False: -> DENIED (403)
    )


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    name: str  # "design.write"
    scope_kind: str  # must be a declared scope kind
    sensitive: bool = False  # metadata for audit and UIs; does not change enforcement


class PermissionCatalog:
    @classmethod
    def from_mapping(
        cls,
        *,
        scopes: Sequence[ScopeKind],
        permissions: Sequence[PermissionSpec],
        roles: Mapping[str, Iterable[str]],
    ) -> "PermissionCatalog": ...
    @classmethod
    def from_file(
        cls, path: Path
    ) -> "PermissionCatalog": ...  # TOML (stdlib tomllib) or JSON, same shape
    def permissions_for(self, role: str) -> frozenset[str]: ...
    def roles(self) -> frozenset[str]: ...
    def spec(self, permission: str) -> PermissionSpec: ...
    def scope_kind(self, name: str) -> ScopeKind: ...
    def roles_granting(self, permission: str) -> frozenset[str]: ...
    def to_mapping(self) -> dict[str, Any]: ...  # round-trips with from_mapping
```

Validation in `from_mapping` (raise `CatalogError` listing ALL problems, not just the first):

- duplicate permission names; permission with an undeclared scope kind;
- a role granting an undeclared permission;
- empty role name, empty permission name, names not matching `[a-z][a-z0-9_.]*` for permissions;
- a role with no permissions is allowed (a read-only-nothing role is legal) but logged at debug;
- the catalog is immutable after build (return `frozenset`/`MappingProxyType`).

Accept `StrEnum` members anywhere a name is expected (ARTISEVM passes `Permission.DESIGN_WRITE`);
normalise with `str(value)` once, at the boundary.

TOML shape (document it; used by ARTISEVM's generator in AUTHZ-019 only if it prefers a file):

```toml
[[scopes]]
name = "studio"
hide_existence = true

[[permissions]]
name = "design.write"
scope = "studio"
sensitive = false

[roles]
TIT = ["design.write", "design.read"]
```

## Acceptance criteria

- [ ] Every validation above has a test with the exact set of reported problems.
- [ ] A catalog with the ARTISEVM shape (39 permissions, 6 roles, 2 scope kinds) builds and
  `to_mapping()` -> `from_mapping()` is the identity (use a trimmed fixture, not ARTISEVM's file).
- [ ] `permissions_for("unknown")` raises `CatalogError`.
- [ ] Thread-safe by immutability; a test mutates a returned set and the catalog is unaffected.
- [ ] `tomllib` is stdlib on 3.11+, so no new dependency.

## Out of scope

Reading the catalog from a database (a catalog is code/config, versioned with the application).
