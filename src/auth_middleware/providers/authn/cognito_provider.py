from time import time, time_ns
from typing import List, Type, Union

import httpx
from jose import jwk
from jose.utils import base64url_decode

from auth_middleware.logging import logger
from auth_middleware.providers.authn.cognito_settings import settings
from auth_middleware.providers.authn.jwt_provider import JWTProvider
from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings
from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
from auth_middleware.providers.exceptions.aws_exception import AWSException
from auth_middleware.types.jwt import JWK, JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User


class CognitoProvider(JWTProvider):

    def __new__(
        cls,
        settings: JWTProviderSettings = None,
        permissions_provider: Union[
            Type[PermissionsProvider], PermissionsProvider
        ] = None,
        groups_provider: Union[Type[GroupsProvider], GroupsProvider] = None,
    ):
        logger.debug("Creating CognitoProvider instance")

        if not hasattr(cls, "instance"):
            cls.instance = super(CognitoProvider, cls).__new__(cls)
        return cls.instance

    def __init__(
        self,
        settings: JWTProviderSettings = None,
        permissions_provider: Union[
            Type[PermissionsProvider], PermissionsProvider
        ] = None,
        groups_provider: Union[Type[GroupsProvider], GroupsProvider] = None,
    ) -> None:

        logger.debug("Initializing CognitoProvider instance")

        if not getattr(self.__class__, "_initialized", False):  # Avoid reinitialization

            if not settings:
                raise ValueError("Settings must be provided")

            # TODO: Refactor this
            # Lazy initialization for PermissionsProvider
            if permissions_provider:
                if isinstance(permissions_provider, type) and issubclass(
                    permissions_provider, PermissionsProvider
                ):
                    logger.debug("Initializing PermissionsProvider")
                    permissions_provider = permissions_provider()
                elif isinstance(permissions_provider, PermissionsProvider):
                    logger.debug("Setting PermissionsProvider")
                    permissions_provider = permissions_provider
                else:
                    raise ValueError(
                        "permissions_provider must be a PermissionsProvider or a subclass thereof"
                    )

            # TODO: Refactor this
            # Lazy initialization for GroupsProvider
            if groups_provider:
                if isinstance(groups_provider, type) and issubclass(
                    groups_provider, GroupsProvider
                ):
                    logger.debug("Initializing GroupsProvider")
                    groups_provider = groups_provider()
                elif isinstance(groups_provider, GroupsProvider):
                    logger.debug("Setting GroupsProvider")
                    groups_provider = groups_provider
                else:
                    raise ValueError(
                        "groups_provider must be a GroupsProvider or a subclass thereof"
                    )

            super().__init__(
                settings=settings,
                permissions_provider=permissions_provider,
                groups_provider=groups_provider,
            )
            self.__class__._initialized = True

    async def get_keys(self) -> List[JWK]:
        """Get keys from AWS Cognito

        Returns:
            List[JWK]: a list of JWK keys
        """
        # TODO: Control errors
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self._settings.jwks_url_template.format(
                    self._settings.user_pool_region,
                    self._settings.user_pool_id,
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
            time_ns() + self._settings.jwks_cache_interval * 60 * 1000000000
        )

        usage_counter: int = self._settings.jwks_cache_usages
        jks: JWKS = JWKS(keys=keys, timestamp=timestamp, usage_counter=usage_counter)

        return jks

    async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:

        if self._settings.jwt_token_verification_disabled:
            return True

        logger.debug("Verifying token through signature")

        hmac_key_candidate = await self._get_hmac_key(token)

        if not hmac_key_candidate:
            # TODO: Custom exception
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
