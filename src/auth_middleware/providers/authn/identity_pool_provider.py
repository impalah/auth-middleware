"""
Identity Pool Provider for AWS Cognito Identity Pool support.

This module extends CognitoProvider to add AWS Cognito Identity Pool capabilities,
allowing JWT tokens from User Pools to be exchanged for temporary AWS credentials.
"""

import logging

from auth_middleware.providers.authn.cognito_provider import CognitoProvider
from auth_middleware.providers.authn.identity_pool_client import CognitoIdentityClient
from auth_middleware.providers.authn.identity_pool_settings import IdentityPoolSettings
from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
from auth_middleware.types.aws_credentials import AWSCredentials
from auth_middleware.types.jwt import JWTAuthorizationCredentials

logger = logging.getLogger(__name__)


class IdentityPoolProvider(CognitoProvider):
    """Cognito Provider with Identity Pool support for AWS credentials.

    This class extends CognitoProvider to enable exchange of JWT tokens from
    Cognito User Pool for temporary AWS credentials via Cognito Identity Pool.

    Attributes:
        identity_pool_client: Client for Cognito Identity Pool API operations
        _credentials_cache: Cache for AWS credentials (keyed by identity_id)
        _identity_id_cache: Cache for identity IDs (keyed by user_id)

    Example:
        ```python
        from identity_pool_settings import IdentityPoolSettings

        settings = IdentityPoolSettings(
            user_pool_region="us-east-1",
            user_pool_id="us-east-1_AbCdEfGhI",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            credentials_duration=3600,
        )

        provider = IdentityPoolProvider(settings=settings)

        # Get AWS credentials from JWT token
        credentials = await provider.get_aws_credentials(jwt_token)

        # Use with boto3
        import boto3
        s3 = boto3.client('s3', **credentials.to_boto3_dict())
        ```
    """

    def __init__(
        self,
        settings: IdentityPoolSettings | None = None,
        permissions_provider: type[PermissionsProvider]
        | PermissionsProvider
        | None = None,
        groups_provider: type[GroupsProvider] | GroupsProvider | None = None,
    ) -> None:
        """Initialize Identity Pool Provider.

        Args:
            settings: Identity Pool settings (extends CognitoAuthzProviderSettings)
            permissions_provider: Optional permissions provider
            groups_provider: Optional groups provider

        Raises:
            ValueError: If settings is not IdentityPoolSettings
        """
        if settings is not None and not isinstance(settings, IdentityPoolSettings):
            raise ValueError("IdentityPoolProvider requires IdentityPoolSettings")

        super().__init__(
            settings=settings,
            permissions_provider=permissions_provider,
            groups_provider=groups_provider,
        )

        if settings:
            # Initialize Identity Pool client
            self.identity_pool_client = CognitoIdentityClient(
                region=settings.identity_pool_region,
                identity_pool_id=settings.identity_pool_id,
                user_pool_id=settings.user_pool_id,
            )

            # Credential caching
            self._credentials_cache: dict[str, AWSCredentials] = {}
            self._identity_id_cache: dict[str, str] = {}

            logger.debug(
                f"IdentityPoolProvider initialized with pool {settings.identity_pool_id}"
            )

    async def get_aws_credentials(
        self,
        token: JWTAuthorizationCredentials | str,
    ) -> AWSCredentials:
        """Get temporary AWS credentials from Cognito Identity Pool.

        This method exchanges a JWT token from Cognito User Pool for temporary
        AWS credentials via Cognito Identity Pool. Credentials are cached and
        reused if not expired.

        Args:
            token: JWT token from Cognito User Pool (string or JWTAuthorizationCredentials)

        Returns:
            AWSCredentials with access key, secret, session token, and expiration

        Raises:
            ValueError: If Identity Pool is not configured
            httpx.HTTPError: If AWS API calls fail

        Example:
            ```python
            # With JWT token string
            credentials = await provider.get_aws_credentials(jwt_token_string)

            # With JWTAuthorizationCredentials
            credentials = await provider.get_aws_credentials(jwt_credentials)

            # Check expiration
            if credentials.is_expired():
                credentials = await provider.get_aws_credentials(jwt_token)
            ```
        """
        if not hasattr(self, "identity_pool_client"):
            raise ValueError("Identity Pool is not configured for this provider")

        # Convert token to string if needed
        token_str = str(token) if hasattr(token, "__str__") else token

        # Extract user_id from token for caching
        if isinstance(token, JWTAuthorizationCredentials):
            user_id = token.claims.get("sub", "")
        else:
            # If token is just a string, we can't extract user_id efficiently
            # Fall back to not using identity_id cache
            user_id = ""

        # Check if we have cached credentials that are still valid
        if user_id and user_id in self._identity_id_cache:
            identity_id = self._identity_id_cache[user_id]

            if identity_id in self._credentials_cache:
                credentials = self._credentials_cache[identity_id]

                # Check if credentials are still valid (with 5-minute buffer)
                if credentials.time_until_expiration() > 300:
                    logger.debug(
                        f"Using cached credentials for {identity_id}, "
                        f"expires in {credentials.time_until_expiration():.0f}s"
                    )
                    return credentials
                else:
                    logger.debug(
                        f"Cached credentials for {identity_id} expired or expiring soon"
                    )

        # Get fresh credentials from AWS
        logger.debug("Fetching new AWS credentials from Identity Pool")
        credentials = await self.identity_pool_client.get_credentials(token_str)

        # Cache credentials and identity_id
        if user_id:
            self._identity_id_cache[user_id] = credentials.identity_id

        self._credentials_cache[credentials.identity_id] = credentials

        logger.debug(
            f"Obtained new AWS credentials for {credentials.identity_id}, "
            f"expires at {credentials.expiration}"
        )

        return credentials

    async def clear_credentials_cache(self, user_id: str | None = None):
        """Clear cached credentials.

        Args:
            user_id: Optional user ID to clear cache for specific user.
                    If None, clears entire cache.

        Example:
            ```python
            # Clear specific user's credentials
            await provider.clear_credentials_cache(user_id="user-123")

            # Clear all cached credentials
            await provider.clear_credentials_cache()
            ```
        """
        if user_id:
            if user_id in self._identity_id_cache:
                identity_id = self._identity_id_cache[user_id]
                self._credentials_cache.pop(identity_id, None)
                self._identity_id_cache.pop(user_id, None)
                logger.debug(f"Cleared cached credentials for user {user_id}")
        else:
            self._credentials_cache.clear()
            self._identity_id_cache.clear()
            logger.debug("Cleared all cached credentials")

    async def close(self):
        """Close Identity Pool client and cleanup resources.

        Example:
            ```python
            provider = IdentityPoolProvider(settings=settings)
            try:
                credentials = await provider.get_aws_credentials(token)
            finally:
                await provider.close()
            ```
        """
        if hasattr(self, "identity_pool_client"):
            await self.identity_pool_client.close()
            logger.debug("Identity Pool client closed")

    async def __aenter__(self):
        """Context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.close()
