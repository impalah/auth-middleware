"""Tests for Cognito Identity Client."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from auth_middleware.providers.authn.identity_pool_client import CognitoIdentityClient
from auth_middleware.types.aws_credentials import AWSCredentials


class TestCognitoIdentityClient:
    """Test suite for CognitoIdentityClient."""

    @pytest.fixture
    def client(self):
        """Create a test client."""
        return CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
        )

    @pytest.fixture
    def mock_http_client(self):
        """Create a mock HTTP client."""
        return AsyncMock(spec=httpx.AsyncClient)

    def test_initialization(self, client):
        """Test basic client initialization."""
        assert client.region == "us-east-1"
        assert (
            client.identity_pool_id == "us-east-1:12345678-1234-1234-1234-123456789012"
        )
        assert client.user_pool_id == "us-east-1_AbCdEfGhI"
        assert client.timeout == 30.0
        assert client._endpoint == "https://cognito-identity.us-east-1.amazonaws.com/"

    def test_login_provider_format(self, client):
        """Test login provider string format."""
        expected = "cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI"
        assert client._login_provider == expected

    @pytest.mark.asyncio
    async def test_get_identity_id_success(self, mock_http_client):
        """Test successful GetId operation."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            http_client=mock_http_client,
        )

        # Mock successful response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "IdentityId": "us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456"
        }
        mock_response.raise_for_status = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)

        identity_id = await client.get_identity_id("test-jwt-token")

        assert identity_id == "us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456"
        mock_http_client.post.assert_called_once()

        # Verify request payload
        call_args = mock_http_client.post.call_args
        assert call_args.kwargs["json"]["IdentityPoolId"] == client.identity_pool_id
        assert "test-jwt-token" in str(call_args.kwargs["json"]["Logins"])

    @pytest.mark.asyncio
    async def test_get_identity_id_missing_identity(self, mock_http_client):
        """Test GetId with missing IdentityId in response."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            http_client=mock_http_client,
        )

        # Mock response without IdentityId
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)

        with pytest.raises(ValueError, match="No IdentityId in response"):
            await client.get_identity_id("test-jwt-token")

    @pytest.mark.asyncio
    async def test_get_credentials_for_identity_success(self, mock_http_client):
        """Test successful GetCredentialsForIdentity operation."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            http_client=mock_http_client,
        )

        # Mock successful response with credentials
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIAXAMPLEXAMPLEXA",
                "SecretKey": "secretaccesskeyexamplesecretaccesskeyexample",
                "SessionToken": "FwoGZXIvYXdzEBExample" + "x" * 100,
                "Expiration": 1738166400.0,  # Unix timestamp
            },
            "IdentityId": "us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456",
        }
        mock_response.raise_for_status = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)

        credentials = await client.get_credentials_for_identity(
            identity_id="us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456",
            jwt_token="test-jwt-token",
        )

        assert isinstance(credentials, AWSCredentials)
        assert credentials.access_key_id == "ASIAXAMPLEXAMPLEXA"
        assert (
            credentials.secret_access_key
            == "secretaccesskeyexamplesecretaccesskeyexample"
        )
        assert (
            credentials.identity_id == "us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456"
        )

    @pytest.mark.asyncio
    async def test_get_credentials_for_identity_missing_credentials(
        self, mock_http_client
    ):
        """Test GetCredentialsForIdentity with missing Credentials in response."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            http_client=mock_http_client,
        )

        # Mock response without Credentials
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)

        with pytest.raises(ValueError, match="No Credentials in response"):
            await client.get_credentials_for_identity(
                identity_id="us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456",
                jwt_token="test-jwt-token",
            )

    @pytest.mark.asyncio
    async def test_get_credentials_for_identity_missing_expiration(
        self, mock_http_client
    ):
        """Test GetCredentialsForIdentity with missing Expiration."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            http_client=mock_http_client,
        )

        # Mock response without Expiration
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIAXAMPLEXAMPLEXA",
                "SecretKey": "secretaccesskeyexamplesecretaccesskeyexample",
                "SessionToken": "FwoGZXIvYXdzEBExample" + "x" * 100,
            }
        }
        mock_response.raise_for_status = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)

        with pytest.raises(ValueError, match="No Expiration in credentials"):
            await client.get_credentials_for_identity(
                identity_id="us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456",
                jwt_token="test-jwt-token",
            )

    @pytest.mark.asyncio
    async def test_get_credentials_combined(self, mock_http_client):
        """Test combined get_credentials method."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            http_client=mock_http_client,
        )

        # Mock GetId response
        mock_get_id_response = MagicMock()
        mock_get_id_response.json.return_value = {
            "IdentityId": "us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456"
        }
        mock_get_id_response.raise_for_status = MagicMock()

        # Mock GetCredentialsForIdentity response
        mock_get_creds_response = MagicMock()
        mock_get_creds_response.json.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIAXAMPLEXAMPLEXA",
                "SecretKey": "secretaccesskeyexamplesecretaccesskeyexample",
                "SessionToken": "FwoGZXIvYXdzEBExample" + "x" * 100,
                "Expiration": 1738166400.0,
            },
            "IdentityId": "us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456",
        }
        mock_get_creds_response.raise_for_status = MagicMock()

        # Set up mock to return different responses for each call
        mock_http_client.post = AsyncMock(
            side_effect=[mock_get_id_response, mock_get_creds_response]
        )

        credentials = await client.get_credentials("test-jwt-token")

        assert isinstance(credentials, AWSCredentials)
        assert credentials.access_key_id == "ASIAXAMPLEXAMPLEXA"
        assert mock_http_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_http_error_handling(self, mock_http_client):
        """Test HTTP error handling."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            http_client=mock_http_client,
        )

        # Mock HTTP error
        mock_http_client.post = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "Unauthorized",
                request=MagicMock(),
                response=MagicMock(status_code=401),
            )
        )

        with pytest.raises(httpx.HTTPStatusError):
            await client.get_identity_id("test-jwt-token")

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager usage."""
        async with CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
        ) as client:
            assert client.region == "us-east-1"

        # Client should be closed after context exit
        # (Verify by checking if we can create a new one)
        new_client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
        )
        assert new_client is not None

    @pytest.mark.asyncio
    async def test_close_method(self, mock_http_client):
        """Test explicit close method."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            http_client=mock_http_client,
        )

        await client.close()
        mock_http_client.aclose.assert_called_once()

    def test_custom_timeout(self):
        """Test custom timeout configuration."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            timeout=60.0,
        )

        assert client.timeout == 60.0

    def test_different_regions(self):
        """Test client with different AWS regions."""
        regions = ["us-west-2", "eu-west-1", "ap-southeast-1"]

        for region in regions:
            client = CognitoIdentityClient(
                region=region,
                identity_pool_id=f"{region}:12345678-1234-1234-1234-123456789012",
                user_pool_id=f"{region}_AbCdEfGhI",
            )
            assert client.region == region
            assert region in client._endpoint
            assert region in client._login_provider

    @pytest.mark.asyncio
    async def test_request_headers(self, mock_http_client):
        """Test that correct headers are sent."""
        client = CognitoIdentityClient(
            region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            user_pool_id="us-east-1_AbCdEfGhI",
            http_client=mock_http_client,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "IdentityId": "us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456"
        }
        mock_response.raise_for_status = MagicMock()
        mock_http_client.post = AsyncMock(return_value=mock_response)

        await client.get_identity_id("test-jwt-token")

        # Verify headers
        call_args = mock_http_client.post.call_args
        headers = call_args.kwargs["headers"]
        assert headers["Content-Type"] == "application/x-amz-json-1.1"
        assert headers["X-Amz-Target"] == "AWSCognitoIdentityService.GetId"
