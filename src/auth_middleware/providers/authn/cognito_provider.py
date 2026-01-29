from time import time, time_ns

import httpx
from jose import jwk
from jose.utils import base64url_decode

from auth_middleware.logging import logger
from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.jwt_provider import JWTProvider
from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
from auth_middleware.providers.exceptions.aws_exception import AWSException
from auth_middleware.services.m2m_detector import M2MTokenDetector
from auth_middleware.types.jwt import JWK, JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User


class CognitoProvider(JWTProvider):
    _instances = {}  # Dict to store separate instances per class

    def __new__(
        cls,
        settings: CognitoAuthzProviderSettings | None = None,
        permissions_provider: type[PermissionsProvider]
        | PermissionsProvider
        | None = None,
        groups_provider: type[GroupsProvider] | GroupsProvider | None = None,
    ) -> CognitoProvider:
        logger.debug("Creating CognitoProvider instance")

        if cls not in cls._instances:
            cls._instances[cls] = super().__new__(cls)
        return cls._instances[cls]

    def __init__(
        self,
        settings: CognitoAuthzProviderSettings | None = None,
        permissions_provider: type[PermissionsProvider]
        | PermissionsProvider
        | None = None,
        groups_provider: type[GroupsProvider] | GroupsProvider | None = None,
    ) -> None:
        logger.debug("Initializing CognitoProvider instance")

        if not getattr(self.__class__, "_initialized", False):  # Avoid reinitialization
            if not settings:
                raise ValueError("Settings must be provided")

            # TODO: Refactor this
            # Lazy initialization for PermissionsProvider
            final_permissions_provider: PermissionsProvider | None = None
            if permissions_provider:
                if isinstance(permissions_provider, type) and issubclass(
                    permissions_provider, PermissionsProvider
                ):
                    logger.debug("Initializing PermissionsProvider")
                    final_permissions_provider = permissions_provider()
                elif isinstance(permissions_provider, PermissionsProvider):
                    logger.debug("Setting PermissionsProvider")
                    final_permissions_provider = permissions_provider
                else:
                    raise ValueError(
                        "permissions_provider must be a PermissionsProvider "
                        "or a subclass thereof"
                    )

            # TODO: Refactor this
            # Lazy initialization for GroupsProvider
            final_groups_provider: GroupsProvider | None = None
            if groups_provider:
                if isinstance(groups_provider, type) and issubclass(
                    groups_provider, GroupsProvider
                ):
                    logger.debug("Initializing GroupsProvider")
                    final_groups_provider = groups_provider()
                elif isinstance(groups_provider, GroupsProvider):
                    logger.debug("Setting GroupsProvider")
                    final_groups_provider = groups_provider
                else:
                    raise ValueError(
                        "groups_provider must be a GroupsProvider or a subclass thereof"
                    )

            super().__init__(
                settings=settings,
                permissions_provider=final_permissions_provider,
                groups_provider=final_groups_provider,
            )
            self._initialized = True

    async def get_keys(self) -> list[JWK]:
        """Get keys from AWS Cognito

        Returns:
            List[JWK]: a list of JWK keys
        """
        # TODO: Control errors
        async with httpx.AsyncClient() as client:
            if not isinstance(self._settings, CognitoAuthzProviderSettings):
                raise ValueError(
                    "CognitoProvider requires CognitoAuthzProviderSettings"
                )
            if not self._settings.jwks_url_template:
                raise ValueError(
                    "jwks_url_template is required in CognitoAuthzProviderSettings"
                )
            response = await client.get(
                self._settings.jwks_url_template.format(
                    self._settings.user_pool_region,
                    self._settings.user_pool_id,
                )
            )
            keys: list[JWK] = response.json()["keys"]
        return keys

    async def load_jwks(
        self,
    ) -> JWKS:
        """Load JWKS credentials from remote Identity Provider

        Returns:
            JWKS: _description_
        """

        # TODO: Control errors
        keys: list[JWK] = await self.get_keys()

        if not isinstance(self._settings, CognitoAuthzProviderSettings):
            raise ValueError("CognitoProvider requires CognitoAuthzProviderSettings")

        timestamp: int = (
            time_ns() + (self._settings.jwks_cache_interval or 20) * 60 * 1000000000
        )

        usage_counter: int = self._settings.jwks_cache_usages or 1000
        jks: JWKS = JWKS(keys=keys, timestamp=timestamp, usage_counter=usage_counter)

        return jks

    async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
        if (
            self._settings
            and hasattr(self._settings, "jwt_token_verification_disabled")
            and self._settings.jwt_token_verification_disabled
        ):
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
            return bool(token.claims["exp"] > time())

        return False

    async def create_user_from_token(self, token: JWTAuthorizationCredentials) -> User:
        """Initializes a domain User object with data recovered from a JWT TOKEN.
        Args:
        token (JWTAuthorizationCredentials): Defaults to Depends(oauth2_scheme).

        Returns:
            User: Domain object.

        """
        # Detect if this is an M2M token
        is_m2m = M2MTokenDetector.is_m2m_token(token)
        client_id = M2MTokenDetector.get_client_id(token) if is_m2m else None

        name_property: str = (
            "username" if "username" in token.claims else "cognito:username"
        )

        # Get groups directly using the groups provider
        groups: list[str] = []
        if self._groups_provider and not is_m2m:
            # M2M tokens typically don't have groups
            groups = await self._groups_provider.fetch_groups(token)

        return User(
            token=str(token),
            jwt_credentials=token,
            groups_provider=self._groups_provider,
            permissions_provider=self._permissions_provider,
            id=token.claims["sub"],
            name=(
                token.claims[name_property]
                if name_property in token.claims
                else token.claims["sub"]
            ),
            email=token.claims["email"] if "email" in token.claims else None,
            groups=groups,
            is_m2m=is_m2m,
            client_id=client_id,
        )
