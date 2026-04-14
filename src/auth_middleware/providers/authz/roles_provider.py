from abc import ABCMeta, abstractmethod

from auth_middleware.types.jwt import JWTAuthorizationCredentials


class RolesProvider(metaclass=ABCMeta):
    """Basic interface for a roles provider

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    @abstractmethod
    async def fetch_roles(self, token: str | JWTAuthorizationCredentials) -> list[str]:
        """Get roles using the token provided

        Args:
            token (JWTAuthorizationCredentials | str): The token containing the claims.

        Raises:
            NotImplementedError: _description_

        Returns:
            List[str]: _description_
        """
        raise NotImplementedError("This method should be overridden by subclasses")
