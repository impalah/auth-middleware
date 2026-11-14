from typing import TYPE_CHECKING

from auth_middleware.contracts.credentials_repository import CredentialsRepository
from auth_middleware.contracts.groups_provider import GroupsProvider
from auth_middleware.contracts.permissions_provider import PermissionsProvider
from auth_middleware.contracts.roles_provider import RolesProvider

if TYPE_CHECKING:  # for type checkers; at runtime the import is lazy (below)
    from auth_middleware.contracts.jwt_provider import JWTProvider

# JWTProvider is loaded lazily to avoid a circular import:
# types/user.py → contracts (this __init__) → contracts/jwt_provider.py → types/user.py
# Lazy loading defers jwt_provider.py until User is fully initialised.


def __getattr__(name: str) -> object:
    if name == "JWTProvider":
        from auth_middleware.contracts.jwt_provider import JWTProvider

        return JWTProvider
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "CredentialsRepository",
    "JWTProvider",
    "GroupsProvider",
    "RolesProvider",
    "PermissionsProvider",
]
