# AUTHZ-003 · Authorizer engine and role resolvers

Epic A · Size M · Depends on: 001, 002 · Blocks: 004

## Context

This is the generic version of ARTISEVM's `StudioAuthorizer.authorize` (read it first:
`artisevm/backend/src/artisevm/application/identity/authorization.py`, 69 lines). The rule there:
no active membership (or the tenant does not exist) -> "not visible"; a member without the permission
-> "denied" naming it; the token's groups play no part.

## Scope

`src/auth_middleware/authz/engine.py`, `src/auth_middleware/authz/resolvers.py`,
`tests/authz/test_engine.py`, `tests/authz/test_resolvers.py`. Uses the in-memory store of AUTHZ-006
only through a local test fake until 006 lands.

## Design

```python
class RoleResolver(Protocol):
    async def resolve(
        self, principal: Principal, scope: ScopeRef
    ) -> ResolvedRoles | None: ...


@dataclass(frozen=True, slots=True)
class ResolvedRoles:
    roles: frozenset[str]
    attributes: Mapping[str, Any] = field(default_factory=dict)


class AssignmentRoleResolver:  # wraps an AssignmentStore
    def __init__(self, store: AssignmentStore) -> None: ...

    # returns ResolvedRoles({assignment.role}, assignment.attributes) for an ACTIVE assignment, else None


class GroupRoleResolver:  # token groups -> role, for one scope kind
    def __init__(
        self, mapping: Mapping[str, str], *, scope_kind: str = GLOBAL_KIND
    ) -> None: ...

    # for a scope of that kind: roles = {mapping[g] for g in principal.groups if g in mapping}; None if empty


class Authorizer:
    def __init__(
        self, catalog: PermissionCatalog, resolvers: Sequence[RoleResolver]
    ) -> None: ...
    async def authorize(
        self, principal: Principal, permission: str, scope: ScopeRef
    ) -> AuthzContext: ...
    async def check(
        self, principal, permission, scope
    ) -> DecisionKind: ...  # never raises for ALLOWED/NOT_VISIBLE/DENIED
```

`authorize` algorithm (write it as the docstring):

1. `spec = catalog.spec(permission)` (raises `UnknownPermissionError`: programming error).
2. `spec.scope_kind` must equal `scope.kind`, else `ScopeKindMismatchError` (programming error).
3. Ask every resolver; keep the non-`None` results. **Union** the roles (additive model) and merge
   `attributes` (later resolvers win on key clashes; document it).
4. No result at all: if `catalog.scope_kind(scope.kind).hide_existence` -> raise `ScopeNotVisibleError`,
   else raise `PermissionDeniedError(permission, scope)`.
5. `granted = union(catalog.permissions_for(r) for r in roles)`; `permission not in granted` ->
   `PermissionDeniedError(permission, scope)`.
6. Return `AuthzContext(principal, scope, roles, granted, attributes)`.

Resolvers run **sequentially in declaration order**, not concurrently: stores may share one database
session (ARTISEVM) and a session is not safe for concurrent use. Say so in the docstring.

## Acceptance criteria

- [ ] Table-driven test: roles x permissions x {member, non-member, revoked, unknown scope} gives the
  exact outcome of the algorithm (build the table from a small catalog; add one row per rule above).
- [ ] `hide_existence=False` scope kind returns `DENIED` (403) when there is no assignment
  (this reproduces ARTISEVM's platform-admin 403).
- [ ] Group resolver: two groups mapping to two roles yield both; unmapped groups yield `None`; a
  resolver for kind `global` is ignored for a `studio` scope.
- [ ] A `REVOKED` assignment behaves exactly like no assignment.
- [ ] `check()` returns the kind without raising; `authorize()` raises the matching error.
- [ ] Exceptions never contain the principal's e-mail or token (they may carry ids and permission names).
- [ ] No I/O besides the resolvers; no logging of principal data above debug level.

## Out of scope

Caching (012), audit (013), FastAPI (005).
