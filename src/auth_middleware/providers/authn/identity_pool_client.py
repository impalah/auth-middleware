"""
Async HTTP client for AWS Cognito Identity Pool API.

This module provides an async client for interacting with AWS Cognito Identity Pool
to exchange JWT tokens for temporary AWS credentials.
"""

import logging
from datetime import datetime

import httpx

from auth_middleware.types.aws_credentials import AWSCredentials

logger = logging.getLogger(__name__)


class CognitoIdentityClient:
    """Async client for AWS Cognito Identity Pool operations.

    This client handles communication with AWS Cognito Identity Pool API,
    including GetId and GetCredentialsForIdentity operations.

    Attributes:
        region: AWS region for the Identity Pool
        identity_pool_id: Cognito Identity Pool ID
        user_pool_id: Cognito User Pool ID (for login provider)
        http_client: Optional httpx AsyncClient for HTTP operations
        timeout: Request timeout in seconds

    Example:
        ```python
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
        )

        identity_id = await client.get_identity_id(jwt_token)
        credentials = await client.get_credentials_for_identity(
            identity_id=identity_id,
            jwt_token=jwt_token,
        )
        ```
    """

    def __init__(
        self,
        region: str,
        identity_pool_id: str,
        user_pool_id: str,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ):
        """Initialize Cognito Identity client.

        Args:
            region: AWS region for the Identity Pool
            identity_pool_id: Cognito Identity Pool ID
            user_pool_id: Cognito User Pool ID
            http_client: Optional httpx AsyncClient (creates one if not provided)
            timeout: Request timeout in seconds
        """
        self.region = region
        self.identity_pool_id = identity_pool_id
        self.user_pool_id = user_pool_id
        self.timeout = timeout
        self._http_client = http_client
        self._endpoint = f"https://cognito-identity.{region}.amazonaws.com/"
        self._login_provider = f"cognito-idp.{region}.amazonaws.com/{user_pool_id}"

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client.

        Returns:
            httpx AsyncClient instance
        """
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self.timeout)
        return self._http_client

    async def close(self):
        """Close HTTP client if it was created internally."""
        if self._http_client is not None:
            await self._http_client.aclose()

    async def get_identity_id(self, jwt_token: str) -> str:
        """Get Cognito Identity ID from JWT token.

        Calls GetId operation to obtain an Identity ID for the authenticated user.

        Args:
            jwt_token: JWT token from Cognito User Pool

        Returns:
            Cognito Identity ID (format: region:uuid)

        Raises:
            httpx.HTTPError: If the request fails
            ValueError: If the response is invalid

        Example:
            ```python
            identity_id = await client.get_identity_id(jwt_token)
            # Output: "us-east-1:12345678-1234-1234-1234-123456789012"
            ```
        """
        payload = {
            "IdentityPoolId": self.identity_pool_id,
            "Logins": {
                self._login_provider: jwt_token,
            },
        }

        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetId",
        }

        logger.debug(
            f"Requesting Identity ID from pool {self.identity_pool_id} "
            f"in region {self.region}"
        )

        response = await self.http_client.post(
            self._endpoint,
            json=payload,
            headers=headers,
        )

        response.raise_for_status()
        data = response.json()

        identity_id = data.get("IdentityId")
        if not identity_id:
            raise ValueError(f"No IdentityId in response: {data}")

        logger.debug(f"Obtained Identity ID: {identity_id}")
        return identity_id

    async def get_credentials_for_identity(
        self,
        identity_id: str,
        jwt_token: str,
    ) -> AWSCredentials:
        """Get temporary AWS credentials for an Identity ID.

        Calls GetCredentialsForIdentity operation to exchange the JWT token
        for temporary AWS credentials.

        Args:
            identity_id: Cognito Identity ID
            jwt_token: JWT token from Cognito User Pool

        Returns:
            AWSCredentials with temporary access key, secret, and session token

        Raises:
            httpx.HTTPError: If the request fails
            ValueError: If the response is invalid

        Example:
            ```python
            credentials = await client.get_credentials_for_identity(
                identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
                jwt_token=jwt_token,
            )

            # Use with boto3
            s3 = boto3.client('s3', **credentials.to_boto3_dict())
            ```
        """
        payload = {
            "IdentityId": identity_id,
            "Logins": {
                self._login_provider: jwt_token,
            },
        }

        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        }

        logger.debug(f"Requesting credentials for Identity ID: {identity_id}")

        response = await self.http_client.post(
            self._endpoint,
            json=payload,
            headers=headers,
        )

        response.raise_for_status()
        data = response.json()

        # Extract credentials from response
        credentials_data = data.get("Credentials")
        if not credentials_data:
            raise ValueError(f"No Credentials in response: {data}")

        # Parse expiration timestamp
        expiration_timestamp = credentials_data.get("Expiration")
        if expiration_timestamp is None:
            raise ValueError(f"No Expiration in credentials: {credentials_data}")

        # AWS returns Unix timestamp in seconds
        expiration = datetime.fromtimestamp(expiration_timestamp)

        # Create AWSCredentials model
        credentials = AWSCredentials(
            access_key_id=credentials_data["AccessKeyId"],
            secret_access_key=credentials_data["SecretKey"],
            session_token=credentials_data["SessionToken"],
            expiration=expiration,
            identity_id=identity_id,
        )

        logger.debug(
            f"Obtained AWS credentials for {identity_id}, "
            f"expires at {credentials.expiration}"
        )

        return credentials

    async def get_credentials(self, jwt_token: str) -> AWSCredentials:
        """Convenience method to get credentials in a single call.

        This method combines get_identity_id and get_credentials_for_identity
        into a single operation.

        Args:
            jwt_token: JWT token from Cognito User Pool

        Returns:
            AWSCredentials with temporary access key, secret, and session token

        Raises:
            httpx.HTTPError: If any request fails
            ValueError: If any response is invalid

        Example:
            ```python
            # One-step credential retrieval
            credentials = await client.get_credentials(jwt_token)
            ```
        """
        identity_id = await self.get_identity_id(jwt_token)
        return await self.get_credentials_for_identity(identity_id, jwt_token)

    async def __aenter__(self):
        """Context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.close()
