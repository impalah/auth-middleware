from abc import ABCMeta, abstractmethod
from time import time, time_ns
from typing import Optional

from jose import jwk
from jose.utils import base64url_decode

from auth_middleware.types import JWK, JWKS, JWTAuthorizationCredentials, User


class JWTAuthProvider(metaclass=ABCMeta):

    def _get_jwks(self) -> JWKS | None:
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
                self.jks: JWKS = self.load_jwks()
            else:
                if self.jks.usage_counter is not None:
                    self.jks.usage_counter -= 1

        except KeyError:
            return None

        return self.jks

    def _get_hmac_key(self, token: JWTAuthorizationCredentials) -> Optional[JWK]:
        jwks: Optional[JWKS] = self._get_jwks()
        if jwks is not None and jwks.keys is not None:
            for key in jwks.keys:
                if key["kid"] == token.header["kid"]:
                    return key
        return None

    @abstractmethod
    def load_jwks(
        self,
    ) -> JWKS: ...

    @abstractmethod
    async def verify_token(
        self,
        token: JWTAuthorizationCredentials,
    ) -> bool: ...

    @abstractmethod
    def create_user_from_token(
        self,
        token: JWTAuthorizationCredentials,
    ) -> User: ...
