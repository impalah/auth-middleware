from abc import ABCMeta, abstractmethod
from time import time, time_ns
from typing import Optional, List

from jose import jwk
from jose.utils import base64url_decode

from auth_middleware.logging import logger
from auth_middleware.types import JWK, JWKS, JWTAuthorizationCredentials, User


class PermissionsProvider(metaclass=ABCMeta):
    """Basic interface for a permissions provider

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    @abstractmethod
    async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> List[str]:
        """Get permissions using the token provided

        Args:
            token (JWTAuthorizationCredentials): _description_

        Raises:
            NotImplementedError: _description_

        Returns:
            List[str]: _description_
        """
        raise NotImplementedError("This method should be overridden by subclasses")
