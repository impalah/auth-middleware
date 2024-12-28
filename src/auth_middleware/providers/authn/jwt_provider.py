from abc import ABCMeta, abstractmethod
from time import time, time_ns
from typing import Optional

from jose import jwk
from jose.utils import base64url_decode

from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings
from auth_middleware.types.jwt import JWK, JWKS, JWTAuthorizationCredentials
from auth_middleware.logging import logger
from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
from auth_middleware.types.user import User


class JWTProvider(metaclass=ABCMeta):
    """Basic interface for a JWT authentication provider

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    _settings: JWTProviderSettings
    _permissions_provider: PermissionsProvider
    _groups_provider: GroupsProvider

    def __init__(
        self,
        settings: JWTProviderSettings = None,
        permissions_provider: PermissionsProvider = None,
        groups_provider: GroupsProvider = None,
    ) -> None:
        self._settings = settings
        self._permissions_provider = permissions_provider
        self._groups_provider = groups_provider

    async def _get_jwks(self) -> JWKS | None:
        """
        Returns a structure that caches the public keys used by the auth provider to sign its JWT tokens.
        Cache is refreshed after a settable time or number of reads (usages)
        """
        reload_cache = False
        try:
            if (
                not hasattr(self, "jks")
                or self.jks.timestamp is None
                or self.jks.timestamp < time_ns()
                or self.jks.usage_counter is None
                or self.jks.usage_counter <= 0
            ):
                reload_cache = True
        except AttributeError:
            # the first time after application startup, self.jks is NOT defined
            reload_cache = True

        try:
            if reload_cache:
                self.jks: JWKS = await self.load_jwks()
                logger.debug("JWKS loaded")
            else:
                if self.jks.usage_counter is not None:
                    self.jks.usage_counter -= 1

        except KeyError:
            return None

        return self.jks

    async def _get_hmac_key(self, token: JWTAuthorizationCredentials) -> Optional[JWK]:
        jwks: Optional[JWKS] = await self._get_jwks()
        if jwks is not None and jwks.keys is not None:
            for key in jwks.keys:
                if key["kid"] == token.header["kid"]:
                    return key
        return None

    @abstractmethod
    async def load_jwks(
        self,
    ) -> JWKS: ...

    @abstractmethod
    async def verify_token(
        self,
        token: JWTAuthorizationCredentials,
    ) -> bool: ...

    @abstractmethod
    async def create_user_from_token(
        self,
        token: JWTAuthorizationCredentials,
    ) -> User: ...
