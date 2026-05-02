from auth_middleware.contracts.credentials_repository import CredentialsRepository
from auth_middleware.contracts.groups_provider import GroupsProvider
from auth_middleware.contracts.permissions_provider import PermissionsProvider
from auth_middleware.contracts.profile_provider import ProfileProvider
from auth_middleware.contracts.roles_provider import RolesProvider

# JWTProvider is loaded lazily to avoid a circular import:
# types/user.py → contracts (this __init__) → contracts/jwt_provider.py → types/user.py
# Lazy loading defers jwt_provider.py until User is fully initialised.


def __getattr__(name: str) -> object:
    if name == "JWTProvider":
        from auth_middleware.contracts.jwt_provider import JWTProvider  # noqa: PLC0415

        return JWTProvider
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "CredentialsRepository",
    "JWTProvider",
    "GroupsProvider",
    "RolesProvider",
    "PermissionsProvider",
    "ProfileProvider",
]
