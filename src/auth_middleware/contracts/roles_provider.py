from abc import ABCMeta, abstractmethod

from auth_middleware.types.jwt import JWTAuthorizationCredentials


class RolesProvider(metaclass=ABCMeta):
    """Abstract contract for a roles provider.

    Implementations must return the list of roles assigned to the
    authenticated user, given either a raw token string or a parsed
    ``JWTAuthorizationCredentials`` object.
    """

    @abstractmethod
    async def fetch_roles(self, token: str | JWTAuthorizationCredentials) -> list[str]:
        """Return the roles for the authenticated user.

        Args:
            token: The token containing the claims, either as a raw string
                   or a parsed ``JWTAuthorizationCredentials`` object.

        Returns:
            List of role name strings (may be empty).
        """
        raise NotImplementedError("This method should be overridden by subclasses")
