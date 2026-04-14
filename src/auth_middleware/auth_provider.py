from abc import ABCMeta, abstractmethod

from auth_middleware.types.user import User


class AuthProvider(metaclass=ABCMeta):
    """Basic interface for an authentication provider

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    @abstractmethod
    async def validate_credentials[TCredentials](self, credentials: TCredentials) -> User: ...

    @abstractmethod
    def create_user_from_credentials[TCredentials](
        self,
        credentials: TCredentials,
    ) -> User: ...
