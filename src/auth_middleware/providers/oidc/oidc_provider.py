"""Generic OpenID Connect JWT provider.

Works with any standards-compliant OIDC identity provider — Authentik,
Keycloak, Auth0, Okta, or any other issuer that exposes a
``.well-known/openid-configuration`` discovery document and a JWKS
endpoint — instead of being tied to a specific cloud vendor.
"""

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
from auth_middleware.contracts.roles_provider import RolesProvider
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.logging import logger
from auth_middleware.providers.oidc.oidc_exception import OidcException
from auth_middleware.providers.oidc.oidc_provider_settings import OidcProviderSettings
from auth_middleware.types.jwt import JWK, JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User


class OidcProvider(JWTProvider):
    """JWT authentication provider for any standards-compliant OIDC issuer.

    Example:
        .. code-block:: python

            from auth_middleware.providers.oidc.oidc_provider import OidcProvider
            from auth_middleware.providers.oidc.oidc_provider_settings import (
                OidcProviderSettings,
            )

            settings = OidcProviderSettings(
                issuer="https://authentik.example.com/application/o/my-app/",
                audience="my-client-id",
            )
            auth_provider = OidcProvider(settings=settings)
    """

    _settings: OidcProviderSettings
    _jwks_uri: str | None

    def __init__(
        self,
        settings: OidcProviderSettings,
        permissions_provider: PermissionsProvider | None = None,
        groups_provider: GroupsProvider | None = None,
        roles_provider: RolesProvider | None = None,
    ) -> None:
        if not isinstance(settings, OidcProviderSettings):
            raise ValueError("OidcProvider requires OidcProviderSettings")

        super().__init__(
            settings=settings,
            permissions_provider=permissions_provider,
            groups_provider=groups_provider,
            roles_provider=roles_provider,
        )
        self._jwks_uri = settings.jwks_uri

    async def _discover_jwks_uri(self) -> str:
        """Resolve the JWKS URL, discovering it from the OIDC discovery
        document the first time it's needed if not explicitly configured.
        The result is cached on the instance so the discovery document is
        not re-fetched on every JWKS refresh.

        Returns:
            str: the JWKS endpoint URL.

        Raises:
            InvalidTokenException: if the discovery document cannot be
                fetched or parsed.
            OidcException: if the discovery document has no 'jwks_uri'.
        """
        if self._jwks_uri:
            return self._jwks_uri

        discovery_url = (
            self._settings.discovery_url
            or f"{self._settings.issuer.rstrip('/')}/.well-known/openid-configuration"
        )

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(discovery_url)
                response.raise_for_status()
                discovery_doc = response.json()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "OIDC discovery endpoint returned {}: {}",
                exc.response.status_code,
                discovery_url,
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to retrieve OIDC discovery document",
            ) from exc
        except httpx.RequestError as exc:
            logger.error(
                "Network error fetching OIDC discovery document from {}: {}",
                discovery_url,
                exc,
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to reach identity provider",
            ) from exc
        except ValueError as exc:
            logger.error(
                "Invalid JSON in OIDC discovery document from {}: {}",
                discovery_url,
                exc,
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OIDC discovery response from identity provider",
            ) from exc

        jwks_uri: str | None = discovery_doc.get("jwks_uri")
        if not jwks_uri:
            logger.error(
                "OIDC discovery document from {} has no 'jwks_uri'", discovery_url
            )
            raise OidcException(
                f"OIDC discovery document at {discovery_url} is missing 'jwks_uri'"
            )

        self._jwks_uri = jwks_uri
        return jwks_uri

    async def get_keys(self) -> list[JWK]:
        """Fetch the JWKS keys from the OIDC identity provider.

        Returns:
            List[JWK]: a list of JWK keys
        """
        jwks_uri = await self._discover_jwks_uri()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(jwks_uri)
                response.raise_for_status()
                keys: list[JWK] = response.json()["keys"]
        except httpx.HTTPStatusError as exc:
            logger.error(
                "OIDC JWKS endpoint returned {}: {}",
                exc.response.status_code,
                jwks_uri,
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to retrieve public keys from identity provider",
            ) from exc
        except httpx.RequestError as exc:
            logger.error("Network error fetching OIDC JWKS from {}: {}", jwks_uri, exc)
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

    async def load_jwks(self) -> JWKS:
        """Load JWKS credentials from the OIDC identity provider.

        Returns:
            JWKS: cached key set with refresh metadata.
        """
        keys = await self.get_keys()

        timestamp: int = (
            time_ns() + (self._settings.jwks_cache_interval or 20) * 60 * 1_000_000_000
        )
        usage_counter: int = self._settings.jwks_cache_usages or 1000

        return JWKS(keys=keys, timestamp=timestamp, usage_counter=usage_counter)

    async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
        if self._settings.jwt_token_verification_disabled:
            return True

        hmac_key_candidate = await self._get_hmac_key(token)
        if not hmac_key_candidate:
            logger.error(
                "No public key found that matches the one present in the TOKEN!"
            )
            raise InvalidTokenException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No public key found!",
            )

        key = import_key(hmac_key_candidate)
        try:
            joserfc_jwt.decode(
                token.jwt_token, key, algorithms=self._settings.algorithms
            )
            self._validate_registered_claims(
                token.claims, leeway=self._settings.jwt_leeway
            )

            registry_options: dict[str, Any] = {
                "iss": {"essential": True, "value": self._settings.issuer}
            }
            if self._settings.audience:
                registry_options["aud"] = {
                    "essential": True,
                    "value": self._settings.audience,
                }
            JWTClaimsRegistry(
                leeway=self._settings.jwt_leeway, **registry_options
            ).validate(token.claims)
        except JoseError:
            return False

        return True

    async def create_user_from_token(self, token: JWTAuthorizationCredentials) -> User:
        """Initializes a domain User object with data recovered from a JWT
        token issued by the configured OIDC provider.

        Args:
            token (JWTAuthorizationCredentials): the verified token.

        Returns:
            User: Domain object.
        """
        groups: list[str] = []
        groups_claim = self._settings.groups_claim
        if groups_claim and groups_claim in token.claims:
            groups = list(token.claims[groups_claim])
        elif self._groups_provider:
            groups = await self._groups_provider.fetch_groups(token)

        roles: list[str] = []
        if self._roles_provider:
            roles = await self._roles_provider.fetch_roles(token)

        return User(
            token=str(token),
            jwt_credentials=token,
            groups_provider=self._groups_provider,
            roles_provider=self._roles_provider,
            permissions_provider=self._permissions_provider,
            id=token.claims["sub"],
            name=token.claims.get(self._settings.username_claim, token.claims["sub"]),
            email=token.claims.get("email"),
            groups=groups,
            roles=roles,
        )
