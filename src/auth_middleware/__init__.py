from .basic_auth_middleware import BasicAuthMiddleware
from .contracts import (
    CredentialsRepository,
    GroupsProvider,
    JWTProvider,
    PermissionsProvider,
    ProfileProvider,
    RolesProvider,
)
from .jwt_auth_middleware import JwtAuthMiddleware

# Version info
__version__ = "0.4.4"


__all__ = [
    "JwtAuthMiddleware",
    "BasicAuthMiddleware",
    # Provider contracts
    "CredentialsRepository",
    "JWTProvider",
    "GroupsProvider",
    "RolesProvider",
    "PermissionsProvider",
    "ProfileProvider",
]
