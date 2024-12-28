from abc import ABCMeta, abstractmethod
from typing import List, Optional

from auth_middleware.types.user_credentials import UserCredentials


class CredentialsRepository(metaclass=ABCMeta):
    """
    Abstract class for database auth repository

    Raises:
        NotImplementedError: _description_
    """

    @abstractmethod
    async def get_by_id(self, *, id: str) -> Optional[UserCredentials]:
        raise NotImplementedError()

    # @abstractmethod
    # async def get_all(self) -> List[UserCredentials]:
    #     raise NotImplementedError()
