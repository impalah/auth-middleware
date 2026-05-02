from time import time_ns
from typing import Any

import httpx
from fastapi import status
from joserfc import jwt as joserfc_jwt
from joserfc.errors import JoseError
from joserfc.jwk import import_key
from joserfc.jwt import JWTClaimsRegistry

from auth_middleware.contracts.groups_provider import GroupsProvider
from auth_middleware.contracts.jwt_provider import JWTProvider
from auth_middleware.contracts.permissions_provider import PermissionsProvider
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.logging import logger
from auth_middleware.providers.azure.azure_exception import AzureException
from auth_middleware.providers.azure.settings import settings
from auth_middleware.types.jwt import JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User


class EntraIDProvider(JWTProvider):
    def __new__(
        cls,
        permissions_provider: PermissionsProvider | None = None,
        groups_provider: GroupsProvider | None = None,
    ) -> EntraIDProvider:
        if not hasattr(cls, "instance"):
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(
        self,
        permissions_provider: PermissionsProvider | None = None,
        groups_provider: GroupsProvider | None = None,
    ) -> None:
        if not hasattr(self, "_initialized"):  # Avoid reinitialization
            super().__init__(
                permissions_provider=permissions_provider,
                groups_provider=groups_provider,
            )
            self._initialized = True

    # TODO: implement correct types
    async def get_keys(self, jwks_uri: str) -> Any:
        """Get keys

        Returns:
            TODO: List[JWK]: a list of JWK
        """
        # TODO: Control errors
        async with httpx.AsyncClient() as client:
            response = await client.get(jwks_uri)
            keys_data: dict[str, str] = response.json()["keys"]
        return keys_data

    async def get_openid_config(self) -> dict[str, str]:
        """Get openid config from entradid

        Returns:
            List[JWK]: a list of JWK
        """
        # TODO: Control errors
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    settings.AUTH_PROVIDER_AZURE_ENTRA_ID_JWKS_URL_TEMPLATE.format(
                        settings.AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID,
                    )
                )
                config_data: dict[str, str] = response.json()
            except Exception as e:
                logger.error("Error in get_openid_config: {}", str(e))
                return {}
        return config_data

    async def load_jwks(
        self,
    ) -> JWKS:
        """Load JWKS credentials from remote Identity Provider

        Returns:
            JWKS: _description_
        """

        # TODO: Control errors

        openid_config = await self.get_openid_config()

        jwks_uri = openid_config["jwks_uri"]

        keys = await self.get_keys(jwks_uri)

        # Convert 'x5c' field in each key from list to string
        for key in keys:
            if "x5c" in key and isinstance(key["x5c"], list):
                key["x5c"] = "".join(key["x5c"])

        timestamp: int = (
            time_ns()
            + getattr(settings, "AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES", 20)
            * 60
            * 1000000000
        )
        usage_counter: int = getattr(
            settings, "AUTH_MIDDLEWARE_JWKS_CACHE_USAGES", 1000
        )
        jks: JWKS = JWKS(keys=keys, timestamp=timestamp, usage_counter=usage_counter)
        return jks

    async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
        """Verifiy token signature

        Args:
            token (JWTAuthorizationCredentials): _description_

        Raises:
            AzureException: _description_

        Returns:
            bool: _description_
        """

        hmac_key_candidate = await self._get_hmac_key(token)

        if not hmac_key_candidate:
            logger.error(
                "No public key found that matches the one present in the TOKEN!"
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No public key found!",
            )

        try:
            rsa_key_dict = {
                "kty": hmac_key_candidate["kty"],
                "kid": hmac_key_candidate["kid"],
                "use": hmac_key_candidate["use"],
                "n": hmac_key_candidate["n"],
                "e": hmac_key_candidate["e"],
            }
            key = import_key(rsa_key_dict)
            audience = settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID
            token_obj = joserfc_jwt.decode(
                token.jwt_token,
                key,
                algorithms=["RS256"],
            )
            if audience:
                claims_registry = JWTClaimsRegistry(
                    aud={"essential": True, "value": audience}
                )
                claims_registry.validate(token_obj.claims)
            return bool(token_obj.claims.get("sub"))
        except JoseError as je:
            logger.error("Error in EntraIDClient: {}", str(je))
            return False
        except Exception as e:
            logger.error("Error in JWTBearerManager: {}", str(e))
            raise AzureException("Error in JWTBearerManager") from e

    async def create_user_from_token(self, token: JWTAuthorizationCredentials) -> User:
        """Initializes a domain User object with data recovered from a JWT TOKEN.
        Args:
        token (JWTAuthorizationCredentials): Defaults to Depends(oauth2_scheme).

        Returns:
            User: Domain object.

        """

        name_property: str = (
            "username" if "username" in token.claims else "preferred_username"
        )

        groups: list[str] = (
            await self._groups_provider.fetch_groups(token)
            if self._groups_provider
            else []
        )

        return User(
            id=token.claims["sub"],
            name=(
                token.claims[name_property]
                if name_property in token.claims
                else token.claims["sub"]
            ),
            groups=groups,
            email=token.claims["email"] if "email" in token.claims else None,
        )
