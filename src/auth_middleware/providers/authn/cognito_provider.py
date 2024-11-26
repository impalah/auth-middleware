from time import time, time_ns
from typing import List

import httpx
from jose import jwk
from jose.utils import base64url_decode

from auth_middleware.types.jwt import JWK, JWKS, JWTAuthorizationCredentials
from auth_middleware.providers.authn.jwt_provider import JWTProvider
from auth_middleware.logging import logger
from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
from auth_middleware.providers.exceptions.aws_exception import AWSException
from auth_middleware.providers.authn.cognito_settings import settings
from auth_middleware.types.user import User


class CognitoProvider(JWTProvider):

    def __new__(
        cls,
        permissions_provider: PermissionsProvider = None,
        groups_provider: GroupsProvider = None,
    ):
        if not hasattr(cls, "instance"):
            cls.instance = super(CognitoProvider, cls).__new__(cls)
        return cls.instance

    def __init__(
        self,
        permissions_provider: PermissionsProvider = None,
        groups_provider: GroupsProvider = None,
    ) -> None:

        if not hasattr(self, "_initialized"):  # Avoid reinitialization
            super().__init__(
                permissions_provider=permissions_provider,
                groups_provider=groups_provider,
            )
            self._initialized = True

    async def get_keys(self) -> List[JWK]:
        """Get keys from AWS Cognito

        Returns:
            List[JWK]: a list of JWK keys
        """
        # TODO: Control errors
        async with httpx.AsyncClient() as client:
            response = await client.get(
                settings.AUTH_PROVIDER_AWS_COGNITO_JWKS_URL_TEMPLATE.format(
                    settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_REGION,
                    settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_ID,
                )
            )
            keys: List[JWK] = response.json()["keys"]
        return keys

    async def load_jwks(
        self,
    ) -> JWKS:
        """Load JWKS credentials from remote Identity Provider

        Returns:
            JWKS: _description_
        """

        # TODO: Control errors
        keys: List[JWK] = await self.get_keys()

        timestamp: int = (
            time_ns()
            + settings.AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES * 60 * 1000000000
        )

        usage_counter: int = settings.AUTH_MIDDLEWARE_JWKS_CACHE_USAGES
        jks: JWKS = JWKS(keys=keys, timestamp=timestamp, usage_counter=usage_counter)

        return jks

    async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:

        if settings.AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED:
            return True

        logger.debug("Verifying token through signature")

        hmac_key_candidate = await self._get_hmac_key(token)

        if not hmac_key_candidate:
            logger.error(
                "No public key found that matches the one present in the TOKEN!"
            )
            raise AWSException("No public key found!")

        hmac_key = jwk.construct(hmac_key_candidate)

        decoded_signature = base64url_decode(token.signature.encode())

        # if crypto is OK, then check expiry date
        if hmac_key.verify(token.message.encode(), decoded_signature):
            return token.claims["exp"] > time()

        return False

    async def create_user_from_token(self, token: JWTAuthorizationCredentials) -> User:
        """Initializes a domain User object with data recovered from a JWT TOKEN.
        Args:
        token (JWTAuthorizationCredentials): Defaults to Depends(oauth2_scheme).

        Returns:
            User: Domain object.

        """

        name_property: str = (
            "username" if "username" in token.claims else "cognito:username"
        )

        return User(
            token=token,
            groups_provider=self._groups_provider,
            permissions_provider=self._permissions_provider,
            id=token.claims["sub"],
            name=(
                token.claims[name_property]
                if name_property in token.claims
                else token.claims["sub"]
            ),
            email=token.claims["email"] if "email" in token.claims else None,
        )
