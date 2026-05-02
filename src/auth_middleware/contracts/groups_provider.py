from abc import ABCMeta, abstractmethod

from auth_middleware.types.jwt import JWTAuthorizationCredentials


class GroupsProvider(metaclass=ABCMeta):
    """Abstract contract for a groups provider.

    Implementations must return the list of groups the authenticated user
    belongs to, given either a raw token string or a parsed
    ``JWTAuthorizationCredentials`` object.
    """

    @abstractmethod
    async def fetch_groups(self, token: str | JWTAuthorizationCredentials) -> list[str]:
        """Return the groups for the authenticated user.

        Args:
            token: The token containing the claims, either as a raw string
                   or a parsed ``JWTAuthorizationCredentials`` object.

        Returns:
            List of group name strings (may be empty).
        """
        raise NotImplementedError("This method should be overridden by subclasses")
