# AUTHZ-011 · Assignment service and `authcli` commands

Epic D · Size M · Depends on: 007 or 009 (either backend is enough to test; use the in-memory one for
unit tests) · Blocks: 014

## Context

Applications must change who has which role, and ARTISEVM has domain rules around that (the "last
owner" rule: `artisevm/backend/src/artisevm/domain/identity/membership.py`, `LastOwnerRequiredError`;
invitations decide who may be assigned which role). The library cannot know those rules but must give a
place to enforce them. The legacy CLI (`src/auth_middleware/cli.py`, entry point `authcli`) has one
command, `get-permissions`, bound to the legacy SQL provider.

## Scope

`src/auth_middleware/authz/service.py`, additions to `src/auth_middleware/cli.py`,
`tests/authz/test_service.py`, `tests/test_cli_authz.py`.

## Design

```python
@dataclass(frozen=True, slots=True)
class AssignmentChange:
    kind: Literal["assign", "change_role", "revoke"]
    principal_id: str
    scope: ScopeRef
    old: Assignment | None
    new_role: str | None

class AssignmentService:
    def __init__(self, admin: AssignmentAdmin, catalog: PermissionCatalog,
                 *, before_change: Sequence[Callable[[AssignmentChange], Awaitable[None]]] = (),
                 after_change: Sequence[Callable[[AssignmentChange, Assignment], Awaitable[None]]] = ()) -> None: ...
    async def assign(self, principal_id, scope, role) -> Assignment
    async def change_role(self, principal_id, scope, role, *, expected_revision: int) -> Assignment
    async def revoke(self, principal_id, scope, *, expected_revision: int) -> Assignment
    async def members(self, scope) -> Sequence[Assignment]
```

- `role` is validated against `catalog.roles()` (`CatalogError`-like `ValueError` subclass
  `UnknownRoleError`), and the role's permissions must belong to the scope's kind (every permission of a
  role assignable in a `studio` scope has `scope_kind == "studio"`; otherwise `ScopeKindMismatchError`).
  Document that this check is why a role is bound to a scope kind through its permissions.
- `before_change` hooks may raise to veto (the application's "last owner" check lives there; the library
  ships no such rule). A veto aborts before any write.
- `after_change` runs after a successful write (cache invalidation of AUTHZ-012, audit of AUTHZ-013 hook
  here; application notifications).
- The service is transport-agnostic: no FastAPI router in the library (applications expose their own
  endpoints with their own invitation flow).

CLI (click, same style as the existing file; keep `get-permissions` untouched):

```
authcli authz assign   --store sqlalchemy|dynamodb --principal SUB --scope studio:UUID --role EDI
authcli authz revoke   ... --expected-revision N
authcli authz list     --principal SUB | --scope studio:UUID
```

Store selection reads `AUTHZ_SQLALCHEMY_DATABASE_URI` (existing setting) or `AUTHZ_DYNAMODB_TABLE`
(new, CLI only; the library code of AUTHZ-004/007/009 reads no environment). Output is plain text, one
assignment per line, never prints tokens.

## Acceptance criteria

- [ ] Service tests with the in-memory store: unknown role rejected; wrong-scope-kind role rejected;
  `before_change` veto leaves the store untouched; `after_change` receives the written assignment;
  stale revision surfaces `RevisionConflictError`.
- [ ] CLI tests with click's `CliRunner` and the in-memory/SQLite store (assign, list, revoke).
- [ ] The legacy `authcli get-permissions` test still passes unchanged.
- [ ] Docstring example shows the "last owner" veto as an application hook (so ARTISEVM's rule maps to it).

## Out of scope

HTTP routers, invitations, e-mail.
