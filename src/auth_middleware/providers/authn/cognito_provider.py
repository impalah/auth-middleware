from time import time_ns

import httpx
from joserfc import jwt as joserfc_jwt
from joserfc.errors import JoseError
from joserfc.jwk import import_key

from auth_middleware.providers.authz.roles_provider import RolesProvider
from auth_middleware.providers.cognito import COGNITO_USERNAME_CLAIM
from auth_middleware.logging import logger
from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.jwt_provider import JWTProvider
from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
from auth_middleware.providers.exceptions.aws_exception import AWSException
from auth_middleware.providers.profile.profile_provider import ProfileProvider
from auth_middleware.services.m2m_detector import M2MTokenDetector
from auth_middleware.types.jwt import JWK, JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User


T_Provider = PermissionsProvider | GroupsProvider | ProfileProvider


def _resolve_provider(
    provider: type[T_Provider] | T_Provider | None,
    base_class: type[T_Provider],
    allow_missing: bool = False,
) -> T_Provider | None:
    """Instantiate *provider* if it is a class; return it as-is if already an
    instance; raise ValueError if it is neither (unless *allow_missing* is True,
    in which case ``None`` is returned silently)."""
    if provider is None:
        return None
    if isinstance(provider, type) and issubclass(provider, base_class):
        logger.debug("Initializing %s", base_class.__name__)
        return provider()
    if isinstance(provider, base_class):
        logger.debug("Setting %s", base_class.__name__)
        return provider
    if allow_missing:
        return None
    raise ValueError(
        f"provider must be a {base_class.__name__} instance or subclass thereof"
    )


class CognitoProvider(JWTProvider):
    _instances = {}  # Dict to store separate instances per class

    def __new__(
        cls,
        settings: CognitoAuthzProviderSettings | None = None,
        permissions_provider: type[PermissionsProvider]
        | PermissionsProvider
        | None = None,
        groups_provider: type[GroupsProvider] | GroupsProvider | None = None,
        roles_provider: type[RolesProvider] | RolesProvider | None = None,
        profile_provider: type[ProfileProvider] | ProfileProvider | None = None,
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
        roles_provider: type[RolesProvider] | RolesProvider | None = None,
        profile_provider: type[ProfileProvider] | ProfileProvider | None = None,
    ) -> None:
        logger.debug("Initializing CognitoProvider instance")

        if not getattr(self.__class__, "_initialized", False):  # Avoid reinitialization
            if not settings:
                raise ValueError("Settings must be provided")

            super().__init__(
                settings=settings,
                permissions_provider=_resolve_provider(
                    permissions_provider, PermissionsProvider
                ),
                groups_provider=_resolve_provider(
                    groups_provider, GroupsProvider, allow_missing=True
                ),
                roles_provider=_resolve_provider(
                    roles_provider, RolesProvider, allow_missing=True
                ),
                profile_provider=_resolve_provider(
                    profile_provider, ProfileProvider
                ),
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

        key = import_key(hmac_key_candidate)
        try:
            joserfc_jwt.decode(token.jwt_token, key, algorithms=["RS256"])
            return True
        except JoseError:
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
            "username" if "username" in token.claims else COGNITO_USERNAME_CLAIM
        )

        # Get groups directly using the groups provider
        groups: list[str] = []
        if self._groups_provider and not is_m2m:
            # M2M tokens typically don't have groups
            groups = await self._groups_provider.fetch_groups(token)

        # Get roles directly using the roles provider
        roles: list[str] = []
        if self._roles_provider and not is_m2m:
            # M2M tokens typically don't have roles
            roles = await self._roles_provider.fetch_roles(token)

        return User(
            token=str(token),
            jwt_credentials=token,
            groups_provider=self._groups_provider,
            roles_provider=self._roles_provider,
            permissions_provider=self._permissions_provider,
            profile_provider=self._profile_provider,
            id=token.claims["sub"],
            name=(
                token.claims[name_property]
                if name_property in token.claims
                else token.claims["sub"]
            ),
            email=token.claims["email"] if "email" in token.claims else None,
            groups=groups,
            roles=roles,
            is_m2m=is_m2m,
            client_id=client_id,
        )
