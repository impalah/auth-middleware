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
from auth_middleware.providers.oidc.token_type import TokenType
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
            JWTClaimsRegistry(
                leeway=self._settings.jwt_leeway,
                iss={"essential": True, "value": self._settings.issuer},
            ).validate(token.claims)
        except JoseError:
            return False

        if self._detect_token_type(token.claims) == TokenType.REFRESH:
            logger.error("Refresh token used as a bearer credential — rejecting")
            return False

        return self._verify_audience(token.claims)

    def _verify_audience(self, claims: dict[str, Any]) -> bool:
        """Check the token was issued for the configured client.

        Standard OIDC ID tokens carry the client id in ``aud``. Many
        providers' *access* tokens don't carry ``aud`` at all - Cognito
        access tokens use ``client_id`` instead - or use it for a
        different-looking resource identifier, so the client id is also
        accepted from any of ``client_id_claims`` (e.g. ``azp``).

        Args:
            claims (dict[str, Any]): The token's decoded claims.

        Returns:
            bool: True if no audience is configured to check against, or if
            the token's aud/client-id claims match it.
        """
        expected = self._settings.audience
        if not expected:
            return True

        token_aud = claims.get("aud")
        if isinstance(token_aud, list):
            if expected in token_aud:
                return True
        elif token_aud == expected:
            return True

        if any(claims.get(c) == expected for c in self._settings.client_id_claims):
            return True

        logger.error(
            "Token audience/client-id does not match configured audience '{}'",
            expected,
        )
        return False

    def _detect_token_type(self, claims: dict[str, Any]) -> TokenType:
        """Classify a token as an ID, access, or refresh token.

        Cognito labels this explicitly via ``token_use``. Most generic OIDC
        providers (Authentik, Keycloak, ...) don't, so absent that claim
        this falls back to a heuristic: a token carrying identity claims
        (``username_claim``, or any of ``identity_claims``) is an ID token;
        one carrying a client-id claim (``client_id_claims``) but no
        identity claims looks like a client_credentials access token;
        otherwise the type can't be determined.

        Args:
            claims (dict[str, Any]): The token's decoded claims.

        Returns:
            TokenType: the detected token type.
        """
        token_use_claim = self._settings.token_use_claim
        if token_use_claim and token_use_claim in claims:
            raw_value = str(claims[token_use_claim]).lower()
            try:
                return TokenType(raw_value)
            except ValueError:
                logger.warning(
                    "Unrecognized '{}' claim value: {}", token_use_claim, raw_value
                )

        if self._has_identity_claim(claims):
            return TokenType.ID
        if any(claims.get(c) for c in self._settings.client_id_claims):
            return TokenType.ACCESS
        return TokenType.UNKNOWN

    def _has_identity_claim(self, claims: dict[str, Any]) -> bool:
        """Whether *claims* carries any claim that identifies a real user."""
        if claims.get(self._settings.username_claim):
            return True
        if any(claims.get(c) for c in self._settings.username_claim_fallbacks):
            return True
        return any(claims.get(c) for c in self._settings.identity_claims)

    def _resolve_username(self, claims: dict[str, Any]) -> str | None:
        """Return the user's display name from the token claims.

        Tries ``username_claim`` first, then each of
        ``username_claim_fallbacks`` in order, then falls back to ``email``.

        Args:
            claims (dict[str, Any]): The token's decoded claims.

        Returns:
            str | None: the resolved display name, or None if none of the
            configured claims are present.
        """
        value = claims.get(self._settings.username_claim)
        if value:
            return str(value)
        for claim_name in self._settings.username_claim_fallbacks:
            value = claims.get(claim_name)
            if value:
                return str(value)
        email = claims.get("email")
        return str(email) if email else None

    def _is_m2m_token(self, claims: dict[str, Any], token_type: TokenType) -> bool:
        """Whether *claims* looks like a machine-to-machine (client_credentials)
        token: an access token issued to a client rather than a user."""
        if not self._settings.detect_m2m_tokens:
            return False
        if token_type != TokenType.ACCESS:
            return False
        return not self._has_identity_claim(claims)

    def _extract_client_id(self, claims: dict[str, Any]) -> str | None:
        """Return the first configured client-id claim present, if any."""
        for claim_name in self._settings.client_id_claims:
            value = claims.get(claim_name)
            if value:
                return str(value)
        return None

    async def create_user_from_token(self, token: JWTAuthorizationCredentials) -> User:
        """Initializes a domain User object with data recovered from a JWT
        token issued by the configured OIDC provider - either a user ID/
        access token, or a machine-to-machine access token.

        Args:
            token (JWTAuthorizationCredentials): the verified token.

        Returns:
            User: Domain object.

        Raises:
            OidcException: if the token has neither a 'sub' claim nor a
                client-id claim to use as the user id.
        """
        claims = token.claims
        token_type = self._detect_token_type(claims)
        is_m2m = self._is_m2m_token(claims, token_type)
        client_id = self._extract_client_id(claims)

        subject = claims.get("sub") or client_id
        if not subject:
            raise OidcException(
                "Token has neither a 'sub' claim nor a client-id claim "
                "(checked: {}) to use as the user id".format(
                    ", ".join(self._settings.client_id_claims)
                )
            )

        groups: list[str] = []
        groups_claim = self._settings.groups_claim
        if self._groups_provider and not is_m2m:
            groups = await self._groups_provider.fetch_groups(token)
        elif groups_claim and groups_claim in claims:
            groups = list(claims[groups_claim])

        roles: list[str] = []
        if self._roles_provider and not is_m2m:
            roles = await self._roles_provider.fetch_roles(token)

        name = self._resolve_username(claims)

        return User(
            token=str(token),
            jwt_credentials=token,
            groups_provider=self._groups_provider,
            roles_provider=self._roles_provider,
            permissions_provider=self._permissions_provider,
            id=subject,
            name=name or client_id or subject,
            email=claims.get("email"),
            groups=groups,
            roles=roles,
            is_m2m=is_m2m,
            client_id=client_id,
        )
