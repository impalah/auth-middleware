from abc import ABCMeta, abstractmethod
from typing import TypeVar

from auth_middleware.types.user import User

TCredentials = TypeVar("TCredentials")


class AuthProvider(metaclass=ABCMeta):
    """Basic interface for an authentication provider

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    @abstractmethod
    async def validate_credentials(self, credentials: TCredentials) -> User: ...

    @abstractmethod
    def create_user_from_credentials(
        self,
        credentials: TCredentials,
    ) -> User: ...
