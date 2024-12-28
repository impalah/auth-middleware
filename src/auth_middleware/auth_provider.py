from abc import ABCMeta, abstractmethod
from time import time, time_ns
from typing import Any, Optional, TypeVar

from starlette.requests import Request

from auth_middleware.logging import logger
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
