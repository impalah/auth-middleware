from abc import ABCMeta, abstractmethod

from auth_middleware.types.jwt import JWTAuthorizationCredentials


class GroupsProvider(metaclass=ABCMeta):
    """Basic interface for a groups provider

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    @abstractmethod
    async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
        """Get groups using the token provided

        Args:
            token (JWTAuthorizationCredentials): _description_

        Raises:
            NotImplementedError: _description_

        Returns:
            List[str]: _description_
        """
        raise NotImplementedError("This method should be overridden by subclasses")
