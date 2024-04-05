from time import time, time_ns

import requests
from jose import JWTError, jwt

from auth_middleware.jwt_auth_provider import JWTAuthProvider
from auth_middleware.logging import logger
from auth_middleware.providers.entra_id.exceptions import AzureException
from auth_middleware.providers.entra_id.settings import settings
from auth_middleware.types import JWK, JWKS, JWTAuthorizationCredentials, User


class EntraIDProvider(JWTAuthProvider):

    def __new__(cls):
        if not hasattr(cls, "instance"):
            cls.instance = super(EntraIDProvider, cls).__new__(cls)
        return cls.instance

    def load_jwks(
        self,
    ) -> JWKS:
        """Load JWKS credentials from remote Identity Provider

        Returns:
            JWKS: _description_
        """

        # TODO: Control errors
        openid_config = requests.get(
            settings.AUTH_PROVIDER_AZURE_ENTRA_ID_JWKS_URL_TEMPLATE.format(
                settings.AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID,
            )
        ).json()
        jwks_uri = openid_config["jwks_uri"]
        keys = requests.get(jwks_uri).json()["keys"]

        # Convert 'x5c' field in each key from list to string
        for key in keys:
            if "x5c" in key and isinstance(key["x5c"], list):
                key["x5c"] = "".join(key["x5c"])

        timestamp: int = (
            time_ns() + settings.AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES * 60 * 1000000000
        )
        usage_counter: int = settings.AUTH_MIDDLEWARE_JWKS_CACHE_USAGES
        jks: JWKS = JWKS(keys=keys, timestamp=timestamp, usage_counter=usage_counter)
        return jks

    def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
        """Verifiy token signature

        Args:
            token (JWTAuthorizationCredentials): _description_

        Raises:
            AzureException: _description_

        Returns:
            bool: _description_
        """

        hmac_key_candidate = self._get_hmac_key(token)

        if not hmac_key_candidate:
            logger.error(
                "No public key found that matches the one present in the TOKEN!"
            )
            raise AzureException("No public key found!")

        # hmac_key = jwk.construct(hmac_key_candidate)

        try:
            rsa_key = {
                "kty": hmac_key_candidate["kty"],
                "kid": hmac_key_candidate["kid"],
                "use": hmac_key_candidate["use"],
                "n": hmac_key_candidate["n"],
                "e": hmac_key_candidate["e"],
            }

            # Decode jwt token
            payload = jwt.decode(
                token.jwt_token,
                rsa_key,
                algorithms=["RS256"],
                audience=settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID,
                options={"verify_at_hash": False},  # Disable at_hash verification
            )
            return False if payload.get("sub") is None else True
        except JWTError as je:
            logger.error("Error in EntraIDClient: %s", str(je))
            return False
        except Exception as e:
            logger.error("Error in JWTBearerManager: %s", str(e))
            raise AzureException("Error in JWTBearerManager")

    def create_user_from_token(self, token: JWTAuthorizationCredentials) -> User:
        """Initializes a domain User object with data recovered from a JWT TOKEN.
        Args:
        token (JWTAuthorizationCredentials): Defaults to Depends(oauth2_scheme).

        Returns:
            User: Domain object.

        """

        name_property: str = (
            "username" if "username" in token.claims else "preferred_username"
        )

        return User(
            id=token.claims["sub"],
            name=(
                token.claims[name_property]
                if name_property in token.claims
                else token.claims["sub"]
            ),
            groups=(
                token.claims["groups"]
                if "groups" in token.claims
                else [str(token.claims["scope"]).split("/")[-1]]
            ),
            email=token.claims["email"] if "email" in token.claims else None,
        )
