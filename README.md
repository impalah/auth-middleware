# Auth Middleware

[![PyPI version](https://badge.fury.io/py/auth-middleware.svg)](https://badge.fury.io/py/auth-middleware)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Coverage](https://img.shields.io/badge/coverage-83%25-green.svg)](https://github.com/impalah/auth-middleware)

**Async Authentication and Authorization Middleware for FastAPI/Starlette Applications**

Auth Middleware is a comprehensive, production-ready authentication and authorization solution for FastAPI and Starlette applications. It provides a pluggable architecture that supports multiple identity providers and authorization backends with async-first design principles.

## Features

### **Authentication Providers**

- **Generic OIDC** — Any standards-compliant OpenID Connect provider — AWS Cognito, Authentik, Keycloak, Auth0, Okta, ... — via `OidcProvider`
- **Azure Entra ID** — Microsoft Azure Active Directory authentication
- **Basic Auth** — Username/password authentication via `BasicAuthMiddleware`
- **Custom Providers** — Extensible architecture via the `JWTProvider` contract

### **Authorization & Access Control**

- **Group-based Authorization** — Role-based access control with user groups
- **Role-based Authorization** — Fine-grained role system
- **Permission-based Authorization** — Fine-grained permission system
- **SQL Backend Support** — PostgreSQL and MySQL for groups/permissions storage via SQLAlchemy
- **Cognito Groups Integration** — Direct integration with AWS Cognito groups (`cognito:groups` claim)
- **Cognito Groups-as-Roles** — Map Cognito groups directly to roles
- **Custom Authorization Providers** — Build your own via the `GroupsProvider`, `RolesProvider` and `PermissionsProvider` contracts

### **Performance & Reliability**

- **Async-First Design** — Built for high-performance async applications
- **JWKS Caching** — Intelligent caching of JSON Web Key Sets
- **Connection Pooling** — Efficient database and HTTP connections
- **Lazy Loading** — User groups and permissions loaded on-demand
- **Error Resilience** — Graceful degradation on provider failures

### **Developer Experience**

- **Type-Safe** — Full type hints throughout, compatible with mypy strict mode
- **FastAPI Integration** — Native dependency injection support
- **Middleware Pattern** — Standard ASGI middleware implementation
- **Environment Configuration** — 12-factor app configuration support
- **Comprehensive Documentation** — Detailed guides and API reference

## Installation

```bash
# pip
pip install auth-middleware

# poetry
poetry add auth-middleware

# uv (recommended)
uv add auth-middleware
```

The core needs no database driver. Optional extras: `auth-middleware[postgres]`,
`auth-middleware[mysql]`, `auth-middleware[sqlalchemy]` (both SQL drivers), `auth-middleware[dynamodb]`
(see [Scoped permissions](#scoped-permissions)) and `auth-middleware[cognito]` (boto3, for `CognitoAuthService`).

## Quick Start

### JWT Authentication with AWS Cognito (via generic OIDC)

```python
from fastapi import FastAPI, Depends, Request
from auth_middleware import JwtAuthMiddleware
from auth_middleware.guards import require_user, require_groups
from auth_middleware.providers.oidc.oidc_provider import OidcProvider
from auth_middleware.providers.oidc.oidc_provider_settings import OidcProviderSettings

app = FastAPI()

auth_settings = OidcProviderSettings(
    issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdef123",
    audience="your-app-client-id",  # recommended: rejects tokens issued for other clients
    jwt_token_verification_disabled=False,
)

app.add_middleware(
    JwtAuthMiddleware,
    auth_provider=OidcProvider(settings=auth_settings),
)


# Requires valid authentication
@app.get("/protected", dependencies=[Depends(require_user())])
async def protected_endpoint(request: Request):
    user = request.state.current_user
    return {"message": f"Hello {user.name}", "user_id": user.id}


# Requires group membership
@app.get("/admin", dependencies=[Depends(require_groups(["admin", "moderator"]))])
async def admin_endpoint(request: Request):
    return {"message": "Admin access granted"}
```

### Azure Entra ID

Set the required environment variables (read at module load time):

```bash
AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID=your-tenant-id
AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID=your-app-client-id
```

```python
from auth_middleware import JwtAuthMiddleware
from auth_middleware.providers.azure.entra_id_provider import EntraIDProvider

app.add_middleware(
    JwtAuthMiddleware,
    auth_provider=EntraIDProvider(),
)
```

### Generic OIDC (Authentik, Keycloak, Auth0, Okta, ...)

Works with any standards-compliant OpenID Connect identity provider — the JWKS is discovered automatically from the issuer's `.well-known/openid-configuration` document.

```python
from auth_middleware import JwtAuthMiddleware
from auth_middleware.providers.oidc.oidc_provider import OidcProvider
from auth_middleware.providers.oidc.oidc_provider_settings import OidcProviderSettings

auth_settings = OidcProviderSettings(
    issuer="https://authentik.example.com/application/o/my-app/",
    audience="your-oidc-client-id",  # recommended: rejects tokens from other clients
)

app.add_middleware(
    JwtAuthMiddleware,
    auth_provider=OidcProvider(settings=auth_settings),
)
```

### Basic Auth

```python
from auth_middleware import BasicAuthMiddleware, hash_password
from auth_middleware.contracts import CredentialsRepository
from auth_middleware.types.user_credentials import UserCredentials

# When creating a user, hash their password once and store the result
# (e.g. hashed_password column) — never store the plaintext password.
stored_hash = hash_password("their-password")


class MyCredentialsRepository(CredentialsRepository):
    async def get_by_id(self, *, id: str) -> UserCredentials | None:
        # Look up the user and return their stored credentials, including
        # the hash produced by hash_password() above
        return UserCredentials(id=id, name="Jane Doe", hashed_password=stored_hash)


app.add_middleware(
    BasicAuthMiddleware,
    credentials_repository=MyCredentialsRepository(),
)
```

## Configuration

### Environment Variables

```bash
# Core middleware — always read from environment
AUTH_MIDDLEWARE_DISABLED=false
AUTH_MIDDLEWARE_LOG_LEVEL=INFO

# Azure Entra ID — always read from environment at module load (required when using EntraIDProvider)
AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID=your-tenant-id
AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID=your-client-id

# Generic OIDC (e.g. AWS Cognito) — optional; alternative to passing values programmatically to OidcProviderSettings
# OIDC_ISSUER=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdef123
# OIDC_AUDIENCE=your-app-client-id
# JWKS_CACHE_INTERVAL=20      # minutes, default 20
# JWKS_CACHE_USAGES=1000      # verifications before refresh, default 1000
```

### SQL-backed Groups and Permissions

```python
from auth_middleware.providers.oidc.oidc_provider import OidcProvider
from auth_middleware.providers.sqlalchemy.sql_groups_provider import SqlGroupsProvider
from auth_middleware.providers.sqlalchemy.sql_permissions_provider import (
    SqlPermissionsProvider,
)
from auth_middleware.providers.sqlalchemy.async_database import AsyncDatabase
from auth_middleware.providers.sqlalchemy.async_database_settings import (
    AsyncDatabaseSettings,
)

AsyncDatabase.configure(
    AsyncDatabaseSettings(database_url="postgresql+asyncpg://user:pass@localhost/mydb")
)

auth_provider = OidcProvider(
    settings=auth_settings,
    groups_provider=SqlGroupsProvider(),
    permissions_provider=SqlPermissionsProvider(),
)

app.add_middleware(JwtAuthMiddleware, auth_provider=auth_provider)
```

### Cognito Groups Provider

```python
from auth_middleware.providers.oidc.oidc_provider import OidcProvider
from auth_middleware.providers.aws.cognito_groups_provider import CognitoGroupsProvider

# Groups extracted directly from the cognito:groups JWT claim
auth_provider = OidcProvider(
    settings=auth_settings,
    groups_provider=CognitoGroupsProvider(),
)
```

## Usage Examples

### Accessing User Information

```python
@app.get("/profile", dependencies=[Depends(require_user())])
async def get_profile(request: Request):
    user = request.state.current_user
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "groups": await user.groups,
        "permissions": await user.permissions,
    }
```

### Role and Permission Guards

```python
from auth_middleware.guards import require_roles, require_permissions


@app.get("/reports", dependencies=[Depends(require_roles(["analyst", "manager"]))])
async def get_reports(request: Request):
    return {"message": "Reports access granted"}


@app.post("/admin/users", dependencies=[Depends(require_permissions(["user.create"]))])
async def create_user(request: Request):
    return {"message": "User creation allowed"}
```

### curl

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/protected
```

## Scoped permissions

Beyond flat groups/roles, `auth_middleware.authz` answers *"may this principal do X in this scope?"* (a tenant,
a project...) from a validated permission catalog and a pluggable assignment store injected at startup. A user
with no assignment in a scope (or a scope that does not exist) gets `404`; a member without the permission gets
`403` naming it.

### 1. Install only what you need

```bash
pip install auth-middleware                  # core + scoped permissions (in-memory store), no DB driver
pip install 'auth-middleware[postgres]'      # + SQLAlchemy, asyncpg
pip install 'auth-middleware[mysql]'         # + SQLAlchemy, aiomysql
pip install 'auth-middleware[sqlalchemy]'    # both SQL drivers
pip install 'auth-middleware[dynamodb]'      # + PynamoDB
```

### 2. Describe permissions and pick a store

```python
from auth_middleware.authz import Authz, PermissionCatalog, PermissionSpec, ScopeKind
from auth_middleware.authz.stores import InMemoryAssignmentStore

catalog = PermissionCatalog.from_mapping(
    scopes=[ScopeKind("project")],
    permissions=[
        PermissionSpec("docs.read", "project"),
        PermissionSpec("docs.write", "project"),
    ],
    roles={"EDITOR": ["docs.read", "docs.write"], "VIEWER": ["docs.read"]},
)

authz = Authz.build(catalog=catalog, store=InMemoryAssignmentStore())  # tests/demos
```

Real backends (the same code works with any of them):

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from auth_middleware.authz.stores import SqlAssignmentStore, DynamoDbAssignmentStore

engine = create_async_engine(
    "postgresql+asyncpg://user:pw@host/db"
)  # or mysql+aiomysql://...
store = SqlAssignmentStore(async_sessionmaker(engine, expire_on_commit=False))
# store = DynamoDbAssignmentStore(table_name="authz-assignments", region="eu-west-1")
authz = Authz.build(catalog=catalog, store=store)
```

The SQL table comes from the Alembic revision `a3f1c9d2b7e4`; the DynamoDB table from
`DynamoDbAssignmentStore.table_definition(name)`.

### 3. Install it and guard routes

```python
from fastapi import Depends
from auth_middleware.authz import AuthzContext, ScopeFromPath, require_permission

authz.install(app)  # after app.add_middleware(JwtAuthMiddleware, ...)


@app.put("/projects/{project_id}/docs")
async def save(
    project_id: str,
    ctx: AuthzContext = Depends(
        require_permission("docs.write", scope=ScopeFromPath("project", "project_id"))
    ),
): ...
```

### 4. Give people roles

```python
from auth_middleware.authz import AssignmentService, ScopeRef

service = AssignmentService(store, catalog)
await service.assign("user-sub", ScopeRef("project", "p-1"), "EDITOR")
```

or from the shell: `authcli authz assign --store sqlalchemy --principal user-sub --scope project:p-1 --role EDITOR`.

Runnable, tested examples: [`examples/authz_example.py`](examples/authz_example.py) and
[`examples/authz_stores_config.py`](examples/authz_stores_config.py). Full guide ("Scoped Permissions" in the
documentation): quick start, catalog, stores, FastAPI integration, operations and migration from the flat
guards, which are unchanged.

## Package Structure

```
auth_middleware/
├── jwt_auth_middleware.py       # JwtAuthMiddleware (ASGI)
├── basic_auth_middleware.py     # BasicAuthMiddleware (ASGI)
├── constants.py                 # AUTH_SCHEME_BASIC, AUTH_SCHEME_BEARER
├── contracts/                   # Abstract base classes
│   ├── jwt_provider.py          #   JWTProvider
│   ├── groups_provider.py       #   GroupsProvider
│   ├── roles_provider.py        #   RolesProvider
│   ├── permissions_provider.py  #   PermissionsProvider
│   └── credentials_repository.py #  CredentialsRepository
├── guards/                      # FastAPI dependency guards
│   ├── functions.py             #   require_user, require_groups, require_roles,
│   │                            #   require_permissions, get_current_user
│   ├── group_checker.py         #   GroupChecker
│   ├── role_checker.py          #   RoleChecker
│   └── permissions_checker.py   #   PermissionsChecker
├── authz/                       # Scoped permissions (catalog, engine, stores, guard)
│   ├── catalog.py, engine.py, runtime.py, guards.py, service.py, cache.py, events.py
│   ├── stores/                  #   memory, sql (SQLAlchemy), dynamodb (PynamoDB)
│   └── testing/                 #   AssignmentStoreContract for your own adapters
├── providers/
│   ├── aws/                     # AWS Cognito groups/roles + auth service (pair with OidcProvider)
│   │   ├── cognito_groups_provider.py
│   │   ├── cognito_groups_as_roles_provider.py
│   │   └── services/            #   Cognito auth service, M2M detector
│   ├── azure/                   # Azure Entra ID
│   │   ├── entra_id_provider.py
│   │   └── settings.py
│   ├── oidc/                    # Generic OIDC (AWS Cognito, Authentik, Keycloak, Auth0, ...)
│   │   ├── oidc_provider.py
│   │   └── oidc_provider_settings.py
│   └── sqlalchemy/              # SQL-backed authorization
│       ├── sql_groups_provider.py
│       ├── sql_permissions_provider.py
│       ├── async_database.py
│       └── async_database_settings.py
└── exceptions/                  # InvalidTokenException, AuthenticationError, …
```

## Architecture

```mermaid
graph TD
    A[HTTP Request] --> B[JwtAuthMiddleware\nor BasicAuthMiddleware]
    B --> C[JWTBearerManager]
    C --> D[JWTProvider\nOidcProvider · EntraIdProvider]
    D --> E[Token Validation\nJWKS cache + exp/iss/aud]
    E --> F[User object]
    F --> G[GroupsProvider\nCognitoGroupsProvider · SqlGroupsProvider]
    F --> H[PermissionsProvider\nSqlPermissionsProvider]
    F --> I[RolesProvider\nCognitoGroupsAsRolesProvider]
    G --> J[request.state.current_user]
    H --> J
    I --> J
    J --> K[Guards\nrequire_user · require_groups\nrequire_roles · require_permissions]
```

## Core Components

| Component | Import path | Description |
| --------- | ----------- | ----------- |
| `JwtAuthMiddleware` | `auth_middleware` | ASGI middleware for JWT authentication |
| `BasicAuthMiddleware` | `auth_middleware` | ASGI middleware for Basic Auth |
| `JWTProvider` | `auth_middleware.contracts` | Abstract base for JWT providers |
| `GroupsProvider` | `auth_middleware.contracts` | Abstract base for group authorization |
| `RolesProvider` | `auth_middleware.contracts` | Abstract base for role authorization |
| `PermissionsProvider` | `auth_middleware.contracts` | Abstract base for permission authorization |
| `CredentialsRepository` | `auth_middleware.contracts` | Abstract base for Basic Auth credential lookup |
| `require_user` | `auth_middleware.guards` | Guard: requires authenticated user |
| `require_groups` | `auth_middleware.guards` | Guard: requires group membership |
| `require_roles` | `auth_middleware.guards` | Guard: requires role membership |
| `require_permissions` | `auth_middleware.guards` | Guard: requires specific permissions |
| `get_current_user` | `auth_middleware.guards` | Dependency: returns current user or `None` |
| `CognitoGroupsProvider` | `auth_middleware.providers.aws.cognito_groups_provider` | Groups from `cognito:groups` claim |
| `CognitoGroupsAsRolesProvider` | `auth_middleware.providers.aws.cognito_groups_as_roles_provider` | Cognito groups mapped as roles |
| `EntraIDProvider` | `auth_middleware.providers.azure.entra_id_provider` | Azure Entra ID JWT provider |
| `OidcProvider` | `auth_middleware.providers.oidc.oidc_provider` | Generic OIDC JWT provider (AWS Cognito, Authentik, Keycloak, Auth0, ...) |
| `SqlGroupsProvider` | `auth_middleware.providers.sqlalchemy.sql_groups_provider` | DB-backed groups |
| `SqlPermissionsProvider` | `auth_middleware.providers.sqlalchemy.sql_permissions_provider` | DB-backed permissions |

### Authenticated User Properties

Available on `request.state.current_user`:

| Property | Type | Description |
| -------- | ---- | ----------- |
| `id` | `str` | Unique identifier from the identity provider |
| `name` | `str \| None` | Display name |
| `email` | `EmailStr \| None` | Email address |
| `groups` | `list[str]` (async) | User groups |
| `roles` | `list[str]` (async) | User roles |
| `permissions` | `list[str]` (async) | User permissions |

## Development

```bash
# Clone and set up
git clone https://github.com/impalah/auth-middleware.git
cd auth-middleware
make venv

# Quality checks
make test          # run test suite
make type-check    # mypy strict
make lint          # ruff
make check         # all checks at once

# Build & publish
make build
make publish
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT — see [LICENSE](LICENSE) for details.

## Links

- **Documentation**: [https://impalah.github.io/auth-middleware/](https://impalah.github.io/auth-middleware/)
- **PyPI Package**: [https://pypi.org/project/auth-middleware/](https://pypi.org/project/auth-middleware/)
- **Source Code**: [https://github.com/impalah/auth-middleware](https://github.com/impalah/auth-middleware)
- **Bug Reports**: [GitHub Issues](https://github.com/impalah/auth-middleware/issues)

---

Created by [impalah](https://github.com/impalah) — Made for modern Python async applications
