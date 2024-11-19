from abc import ABCMeta, abstractmethod
from time import time, time_ns
from typing import Optional, List

from jose import jwk
from jose.utils import base64url_decode

from auth_middleware.logging import logger
from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
from auth_middleware.types import JWK, JWKS, JWTAuthorizationCredentials, User


class SqlPermissionsProvider(PermissionsProvider):
    """Recovers groups from AWS Cognito using the token provided

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> List[str]:
        """Get groups using the token provided

        Args:
            token (JWTAuthorizationCredentials): _description_

        Raises:
            NotImplementedError: _description_

        Returns:
            List[str]: _description_
        """

        return ["read:data", "write:data", "delete:data"]
