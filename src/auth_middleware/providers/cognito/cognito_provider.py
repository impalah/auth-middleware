from time import time, time_ns
from typing import List

import httpx
from jose import jwk
from jose.utils import base64url_decode

from auth_middleware.jwt_auth_provider import JWTAuthProvider
from auth_middleware.logging import logger
from auth_middleware.providers.cognito.exceptions import AWSException
from auth_middleware.providers.cognito.settings import settings
from auth_middleware.types import JWK, JWKS, JWTAuthorizationCredentials, User


class CognitoProvider(JWTAuthProvider):

    def __new__(cls):
        if not hasattr(cls, "instance"):
            cls.instance = super(CognitoProvider, cls).__new__(cls)
        return cls.instance

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

    def __get_groups_from_claims(self, claims: dict) -> List[str]:
        """Extracts groups from claims.

        Args:
            claims (dict): JWT claims.

        Returns:
            List[str]: List of groups.
        """
        return (
            claims["cognito:groups"]
            if "cognito:groups" in claims
            else [str(scope).split("/")[-1] for scope in claims["scope"]]
        )

    def create_user_from_token(self, token: JWTAuthorizationCredentials) -> User:
        """Initializes a domain User object with data recovered from a JWT TOKEN.
        Args:
        token (JWTAuthorizationCredentials): Defaults to Depends(oauth2_scheme).

        Returns:
            User: Domain object.

        """

        name_property: str = (
            "username" if "username" in token.claims else "cognito:username"
        )

        groups: List[str] = (
            self.__get_groups_from_claims(token.claims)
            if "cognito:groups" in token.claims or "scope" in token.claims
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
