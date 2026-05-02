from abc import ABCMeta, abstractmethod

from auth_middleware.types.jwt import JWTAuthorizationCredentials


class PermissionsProvider(metaclass=ABCMeta):
    """Abstract contract for a permissions provider.

    Implementations must return the list of permissions granted to the
    authenticated user, given either a raw token string or a parsed
    ``JWTAuthorizationCredentials`` object.
    """

    @abstractmethod
    async def fetch_permissions(
        self, token: str | JWTAuthorizationCredentials
    ) -> list[str]:
        """Return the permissions for the authenticated user.

        Args:
            token: The token containing the claims, either as a raw string
                   or a parsed ``JWTAuthorizationCredentials`` object.

        Returns:
            List of permission name strings (may be empty).
        """
        raise NotImplementedError("This method should be overridden by subclasses")
