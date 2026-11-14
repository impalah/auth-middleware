# PLAN · Scoped permissions in auth-middleware (extracted from ARTISEVM)

Status: proposed (2026-11-14). Nothing in this plan is implemented yet.
Issues: `documentation/issues/` (index and execution order in `documentation/issues/README.md`).
Target release: `0.7.0` (additive: no existing public name changes).

## 1. Why

ARTISEVM (`/home/linus/projects/pinturilla/artisevm`) uses this library only for **authentication**
(`JwtAuthMiddleware` + a subclass of `OidcProvider`) and for a **coarse group check**
(`GroupChecker`). Its real authorization is its own code: a catalog of 39 permissions, six roles,
memberships stored per tenant ("studio") in its database, a `404`/`403` rule that hides the existence
of tenants, and Row-Level Security bound before the check. The goal is that this mechanism lives
here, generic and reusable, and ARTISEVM keeps only its catalog and its domain rules.

What ARTISEVM has today (verified by reading the code, 2026-11-14):

| Piece | Where (ARTISEVM `backend/src/artisevm/`) | Generic? |
|---|---|---|
| Permission catalog + role x permission matrix, generated from the spec | `domain/identity/permissions.py`, `tools/gen_permissions.py` | The *mechanism* yes, the *content* no |
| `StudioAuthorizer`: `sub` -> membership of the tenant in the route -> role -> permissions; 404 if not a member, 403 naming the permission | `application/identity/authorization.py` | Yes |
| `require_studio_permission(Permission.X)` FastAPI dependency, 43 uses, 32 distinct permissions; `x-permission` published in OpenAPI | `api/authorization.py` | Yes |
| Token-group gates (`require_reader`, `require_writer`, `require_platform_admin`) | `api/dependencies.py`, `platform_api/dependencies.py` | Yes (becomes group -> role mapping) |
| Hardening of bearer validation on top of the library (`BearerSchemeOnly`, `PathScoped`, access-token-only provider, forced JWKS refresh, mandatory audience, refusal of `AUTH_MIDDLEWARE_DISABLED`) | `infrastructure/auth/tokens.py` | Yes (Epic F) |
| Memberships, invitations, "last owner" rule, tenant status gating writes | `domain/identity/*`, `application/identity/*` | **No: stays in ARTISEVM** |
| RLS bound per transaction before authorizing | `infrastructure/db/rls.py`, `composition.py` | The *hook* yes, the SQL no |
| HTMX relying party, web sessions, CSRF, company accounts, guest links | `infrastructure/auth/oidc.py`, `web/*` | **Out of scope** (see section 7) |

## 2. What the library has today and why it does not fit as is

Verified in `src/auth_middleware/` (0.6.2):

- `guards/functions.py` has `require_groups`, `require_roles`, `require_permissions`: **flat any-of
  lists** read from `request.state.current_user` (`User.groups|roles|permissions`, lazy async
  properties filled by an injected provider).
- `PermissionsProvider.fetch_permissions(token)` receives **only the token**. It cannot know *which
  tenant* the request is about (a path parameter) nor consult the request's database transaction.
- `SqlPermissionsProvider` reads a global table `authz_permissions(username, permission)`: no tenant
  column, no roles, no status, no revision. It uses the `AsyncDatabase` **singleton** configured by a
  class method or by environment, not an injected session. `pages_source/extending-authz-providers.rst`
  shows a DynamoDB *groups* provider as documentation only; there is **no DynamoDB code** and no
  `boto3` dependency in `pyproject.toml` (`cognito_auth_service.py` imports it lazily).
- The checkers raise a fixed `HTTPException(403, "Operation not allowed")` and **skip every check when
  `AUTH_MIDDLEWARE_DISABLED` is set** (a process-wide footgun).
- Existing SQL tests mock the session; no test runs against a real database.

So the missing piece is a **scope-aware authorizer**, not another provider.

## 3. Target design

New subpackage `auth_middleware.authz` (everything additive; the old guards and providers stay
untouched and documented as "flat RBAC").

```
Request ──JwtAuthMiddleware──> request.state.current_user (User: id, groups)
   │
   └─ Depends(require_permission("design.write", scope=ScopeFromPath("studio_id")))
        │
        ├─ Authz (built at startup, held in app.state.authz)
        │    ├─ PermissionCatalog   role -> permissions (immutable, validated)
        │    ├─ store_factory(request) -> AssignmentStore   <- SQLAlchemy | DynamoDB | in-memory | app adapter
        │    ├─ RoleResolvers       [stored assignment, token groups -> role mapping]
        │    └─ ErrorPolicy         not visible -> 404, denied -> 403 (+ hooks for the body)
        └─ AuthzContext (principal, scope, role, permissions, attributes) returned to the handler
```

### 3.1 Concepts

- **Principal**: `id` (the token `sub`) plus optional `groups` from the token.
- **Scope**: `ScopeRef(kind, id)`, e.g. `("studio", "<uuid>")`; `ScopeRef.GLOBAL` for platform-wide
  permissions. A scope kind is declared in the catalog; a permission belongs to one scope kind.
- **Assignment**: `(principal_id, scope, role, status, revision, created_at)`. One active assignment
  per principal and scope (the ARTISEVM rule). Statuses: `active`, `revoked`.
- **Role**: a name. **Catalog**: `role -> frozenset[permission]`, additive only (nothing denies, as in
  ARTISEVM doc 05). Permissions may carry flags (`sensitive`) and a scope kind.
- **Decision**: `allowed | not_visible | denied`, with the resolved `role`, `permissions` and free
  `attributes` that a store may attach (ARTISEVM attaches the tenant status).
- **Two failure modes on purpose**: *not visible* (principal has no active assignment in the scope or
  the scope does not exist: indistinguishable, default 404) and *denied* (has an assignment but lacks
  the permission: default 403 naming the permission).

### 3.2 Ports (the dependency-injection surface)

```python
class AssignmentStore(Protocol):  # read side: what the guard needs
    async def get_assignment(
        self, principal_id: str, scope: ScopeRef
    ) -> Assignment | None: ...
    async def list_assignments(
        self, principal_id: str
    ) -> Sequence[Assignment]: ...  # "my scopes"


class AssignmentAdmin(Protocol):  # write side: optional, for the CLI/service
    async def assign(self, assignment: NewAssignment) -> Assignment: ...
    async def change_role(
        self, principal_id, scope, role, *, expected_revision
    ) -> Assignment: ...
    async def revoke(self, principal_id, scope, *, expected_revision) -> Assignment: ...
    async def list_for_scope(self, scope: ScopeRef) -> Sequence[Assignment]: ...


StoreFactory = Callable[[Request], AssignmentStore | Awaitable[AssignmentStore]]
```

The store is resolved **per request** through `StoreFactory`. That is what lets an application hand
the guard a store that shares *its* request-scoped database session (needed for RLS and for one
transaction per request), while a simple deployment passes a singleton store.

### 3.3 Startup wiring (the "configurable by DI at startup" requirement)

```python
authz = Authz.build(
    catalog=PermissionCatalog.from_mapping(roles={...}, scopes={...}),
    store=SqlAlchemyAssignmentStore(
        session_factory=async_sessionmaker
    ),  # or DynamoDbAssignmentStore(table=...)
    # store_factory=lambda request: AppStore(request.state.session),       # per-request alternative
    group_roles={"platform-admins": "PLATFORM_ADMIN"},  # optional
    error_policy=ErrorPolicy(),  # optional hooks
)
authz.install(
    app
)  # app.state.authz, startup/shutdown hooks, refuses AUTH_MIDDLEWARE_DISABLED
```

Nothing reads the environment implicitly and nothing is a module-level singleton in the new code
(the existing `AsyncDatabase` singleton keeps serving the legacy providers).

### 3.4 Storage backends

| Backend | Extra | Notes |
|---|---|---|
| In-memory | none | Tests and examples; also the reference for the contract test-suite |
| SQLAlchemy | `sqlalchemy` (exists) | Table `authz_assignment`; injected `async_sessionmaker` or per-request session; `before_query` hook to bind RLS; Alembic migration |
| DynamoDB | `dynamodb` (new, `aioboto3`) | Single table, `PK=SCOPE#kind#id`, `SK=PRINCIPAL#id`, GSI on principal; conditional writes for `revision` |
| App adapter | none | The application implements `AssignmentStore` over its own tables (ARTISEVM keeps `identity.membership`) |

Every backend must pass the same **store contract test-suite** shipped in
`auth_middleware.authz.testing` so that applications can reuse it for their adapters.

### 3.5 What stays in the application

The catalog content, the domain rules around assignments (last owner, invitations, who may invite
whom), tenant lifecycle (a suspended tenant is read-only: the app reads `Decision.attributes`),
company/guest principals, and the HTMX session layer.

## 4. Epics and phases

| Epic | Issues | Outcome |
|---|---|---|
| A · Core | AUTHZ-001..006 | Model, catalog, engine, runtime, FastAPI guard, in-memory store + contract suite |
| B · SQLAlchemy | AUTHZ-007, 008 | Store, migration, real-database tests |
| C · DynamoDB | AUTHZ-009, 010 | Store, tests, IaC notes |
| D · Operations | AUTHZ-011..013 | Admin service and CLI, optional cache, audit and metrics |
| E · Docs and release | AUTHZ-014 | Sphinx, README, example, CHANGELOG, `0.7.0` |
| F · AuthN hardening upstream | AUTHZ-015..017 | What ARTISEVM patches on top of the library becomes options of the library |
| G · ARTISEVM adoption | AUTHZ-018..022 | Executed **in the ARTISEVM repository**; parity tests first |

Order and parallelism: see `documentation/issues/README.md`. A, B, C, D and E ship as `0.7.0` without touching
ARTISEVM. F can ship as `0.7.x`. G starts only when `0.7.0` is on PyPI (or installed from a path).

## 5. Acceptance of the whole plan

1. ARTISEVM's existing tests `tests/unit/test_studio_authorization.py`,
   `tests/architecture/test_rest_authorization.py` and `tests/architecture/test_hostile_tokens.py`
   pass **unchanged** after Epic G (parity is the acceptance criterion, not new behaviour).
2. All 43 `require_studio_permission` call sites keep their status codes and their problem bodies.
3. The same store contract tests pass on in-memory, SQLAlchemy (PostgreSQL) and DynamoDB.
4. `make check` (ruff, format, mypy strict, bandit) and `make test` pass on Python 3.12 and 3.14.
5. No existing public symbol of 0.6.2 is removed or changes behaviour.

## 6. Risks and how the plan answers them

| Risk | Answer |
|---|---|
| An authorization library that fails open | New guard never bypasses on `AUTH_MIDDLEWARE_DISABLED`; `install` refuses it unless `allow_disabled_for_development=True`; missing store or catalog is a startup error |
| Per-request store vs singleton engine confusion | `StoreFactory` is the only seam; documented with both examples; tested with a store that counts sessions |
| RLS: the check must run inside the tenant-bound transaction | `before_query` hook on the SQL store and the per-request factory; AUTHZ-018 proves it with ARTISEVM's real RLS tests |
| DynamoDB eventual consistency lets a revoked member in | `ConsistentRead=True` on the assignment read (default, documented cost); revision on every write |
| Stale cache keeps a revoked member | Cache is off by default; when on, TTL is short and `AssignmentAdmin` writes invalidate in-process (AUTHZ-012) |
| Catalog typos grant or hide permissions silently | `PermissionCatalog` validates on build; unknown permission at a guard raises at import/startup, not at request time |
| Scope creep into ARTISEVM's web layer | Explicit non-goal (section 7) |
| Python compatibility | Library supports 3.12+: `from __future__ import annotations`, no 3.13-only syntax; CI matrix already exists in `.github/workflows/tests.yml` |

## 7. Non-goals

- Deny rules, permission inheritance down a tree, per-resource ACLs (the `add-hierarchical-permissions`
  skill of the py-backend template covers that; the model here is additive like ARTISEVM doc 05).
- Moving ARTISEVM's HTMX relying party, web sessions, CSRF, company accounts or guest links into the
  library. They are domain-bound; revisit only if a second application needs them.
- Replacing `GroupChecker`, `RoleChecker` or `PermissionsChecker`. They stay for flat RBAC.

## 8. Decisions already taken, and the ones left open

Taken (reason in the issue that implements it):

1. New code under `auth_middleware.authz`, additive, version `0.7.0`.
2. Additive permission model, one active assignment per principal and scope.
3. Store resolved per request through `StoreFactory`; singleton store is the simple case.
4. DynamoDB through `aioboto3` in a new `dynamodb` extra (not `boto3` + threads).
5. ARTISEVM keeps its own membership tables behind an adapter in the first adoption (AUTHZ-018);
   moving them into library tables is a separate, optional decision (AUTHZ-022).

Open (need the owner's answer before the issue that depends on them; each issue repeats its own):

- **Q1** Cache: is a short in-process TTL acceptable at all for ARTISEVM? (Today it reads the database
  on every request.) Blocks AUTHZ-012 only.
- **Q2** DynamoDB test double: `moto`, DynamoDB Local, or an AWS emulator already used elsewhere
  (support for DynamoDB in ARTISEVM's `floci` S3 emulator is **not verified**). Blocks AUTHZ-010.
- **Q3** Publishing: the library's generated HTML folder (now `pages/`, sources in `pages_source/`) is committed. Regenerate it in the
  same PR (`make docs`) or leave it to the release? Blocks AUTHZ-014.
- **Q4** ARTISEVM Epic G needs an ADR (project rule: changing an accepted architecture decision needs
  a new ADR and approval; D-003 describes memberships and groups). Owner approval required before
  AUTHZ-018 starts.
