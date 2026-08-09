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
from auth_middleware.types.jwt import JWK, JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User


class EntraIDProvider(JWTProvider):
    def __init__(
        self,
        permissions_provider: PermissionsProvider | None = None,
        groups_provider: GroupsProvider | None = None,
    ) -> None:
        super().__init__(
            permissions_provider=permissions_provider,
            groups_provider=groups_provider,
        )

    async def get_keys(self, jwks_uri: str) -> list[JWK]:
        """Get keys from the Entra ID JWKS endpoint.

        Args:
            jwks_uri: The JWKS endpoint URL, as returned by the OIDC
                discovery document.

        Returns:
            List[JWK]: a list of JWK keys
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(jwks_uri)
                response.raise_for_status()
                keys: list[JWK] = response.json()["keys"]
        except httpx.HTTPStatusError as exc:
            logger.error(
                "Entra ID JWKS endpoint returned {}: {}",
                exc.response.status_code,
                jwks_uri,
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to retrieve public keys from identity provider",
            ) from exc
        except httpx.RequestError as exc:
            logger.error(
                "Network error fetching Entra ID JWKS from {}: {}", jwks_uri, exc
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to reach identity provider",
            ) from exc
        except (KeyError, ValueError) as exc:
            logger.error("Unexpected JWKS response format from {}: {}", jwks_uri, exc)
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid JWKS response from identity provider",
            ) from exc

        return keys

    async def get_openid_config(self) -> dict[str, Any]:
        """Get the OIDC discovery document for the configured Entra ID tenant.

        Returns:
            dict[str, Any]: the discovery document.
        """
        discovery_url = settings.AUTH_PROVIDER_AZURE_ENTRA_ID_JWKS_URL_TEMPLATE.format(
            settings.AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID,
        )
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(discovery_url)
                response.raise_for_status()
                config_data: dict[str, Any] = response.json()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "Entra ID discovery endpoint returned {}: {}",
                exc.response.status_code,
                discovery_url,
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to retrieve OIDC discovery document",
            ) from exc
        except httpx.RequestError as exc:
            logger.error(
                "Network error fetching Entra ID discovery document from {}: {}",
                discovery_url,
                exc,
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to reach identity provider",
            ) from exc
        except ValueError as exc:
            logger.error(
                "Invalid JSON in Entra ID discovery document from {}: {}",
                discovery_url,
                exc,
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OIDC discovery response from identity provider",
            ) from exc

        return config_data

    async def load_jwks(
        self,
    ) -> JWKS:
        """Load JWKS credentials from remote Identity Provider

        Returns:
            JWKS: cached key set with refresh metadata.
        """

        openid_config = await self.get_openid_config()

        jwks_uri = openid_config.get("jwks_uri")
        if not jwks_uri:
            logger.error("Entra ID discovery document has no 'jwks_uri'")
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OIDC discovery response from identity provider",
            )

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
            self._validate_registered_claims(
                token_obj.claims,
                leeway=settings.AUTH_PROVIDER_AZURE_ENTRA_ID_LEEWAY,
            )
            if audience:
                claims_registry = JWTClaimsRegistry(
                    aud={"essential": True, "value": audience},
                    leeway=settings.AUTH_PROVIDER_AZURE_ENTRA_ID_LEEWAY,
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
