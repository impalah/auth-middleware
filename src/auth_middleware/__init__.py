from .basic_auth_middleware import BasicAuthMiddleware
from .contracts import (
    CredentialsRepository,
    GroupsProvider,
    JWTProvider,
    PermissionsProvider,
    RolesProvider,
)
from .jwt_auth_middleware import JwtAuthMiddleware
from .password_hasher import hash_password, verify_password

# Version info
__version__ = "0.6.0"


__all__ = [
    "JwtAuthMiddleware",
    "BasicAuthMiddleware",
    # Provider contracts
    "CredentialsRepository",
    "JWTProvider",
    "GroupsProvider",
    "RolesProvider",
    "PermissionsProvider",
    # Basic Auth password hashing
    "hash_password",
    "verify_password",
]
