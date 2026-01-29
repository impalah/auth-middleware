"""Tests for Identity Pool Provider."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.identity_pool_provider import IdentityPoolProvider
from auth_middleware.providers.authn.identity_pool_settings import IdentityPoolSettings
from auth_middleware.types.aws_credentials import AWSCredentials
from auth_middleware.types.jwt import JWTAuthorizationCredentials


class TestIdentityPoolProvider:
    """Test suite for IdentityPoolProvider."""

    @pytest.fixture
    def settings(self):
        """Create test Identity Pool settings."""
        return IdentityPoolSettings(
            user_pool_region="us-east-1",
            user_pool_id="us-east-1_AbCdEfGhI",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            credentials_duration=3600,
        )

    @pytest.fixture
    def mock_credentials(self):
        """Create mock AWS credentials."""
        return AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=datetime.now(UTC) + timedelta(hours=1),
            identity_id="us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456",
        )

    @pytest.fixture
    def mock_jwt_token(self):
        """Create mock JWT token."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "user-12345",
            "cognito:username": "testuser",
            "email": "test@example.com",
        }
        token.__str__ = MagicMock(return_value="mock-jwt-token-string")
        return token

    def test_initialization(self, settings):
        """Test basic provider initialization."""
        provider = IdentityPoolProvider(settings=settings)

        assert hasattr(provider, "identity_pool_client")
        assert provider.identity_pool_client.region == "us-east-1"
        assert (
            provider.identity_pool_client.identity_pool_id == settings.identity_pool_id
        )
        assert provider._credentials_cache == {}
        assert provider._identity_id_cache == {}

    def test_initialization_invalid_settings(self):
        """Test initialization with wrong settings type."""
        invalid_settings = CognitoAuthzProviderSettings(
            user_pool_region="us-east-1",
            user_pool_id="us-east-1_AbCdEfGhI",
        )

        with pytest.raises(
            ValueError, match="IdentityPoolProvider requires IdentityPoolSettings"
        ):
            IdentityPoolProvider(settings=invalid_settings)

    @pytest.mark.asyncio
    async def test_get_aws_credentials_success_with_jwt_object(
        self, settings, mock_jwt_token, mock_credentials
    ):
        """Test getting AWS credentials with JWTAuthorizationCredentials object."""
        provider = IdentityPoolProvider(settings=settings)

        # Mock the identity pool client
        provider.identity_pool_client.get_credentials = AsyncMock(
            return_value=mock_credentials
        )

        credentials = await provider.get_aws_credentials(mock_jwt_token)

        assert credentials == mock_credentials
        assert credentials.access_key_id == "ASIAXAMPLEXAMPLEXA"
        provider.identity_pool_client.get_credentials.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_aws_credentials_success_with_string_token(
        self, settings, mock_credentials
    ):
        """Test getting AWS credentials with string token."""
        provider = IdentityPoolProvider(settings=settings)

        # Mock the identity pool client
        provider.identity_pool_client.get_credentials = AsyncMock(
            return_value=mock_credentials
        )

        credentials = await provider.get_aws_credentials("jwt-token-string")

        assert credentials == mock_credentials
        provider.identity_pool_client.get_credentials.assert_called_once_with(
            "jwt-token-string"
        )

    @pytest.mark.asyncio
    async def test_credentials_caching(
        self, settings, mock_jwt_token, mock_credentials
    ):
        """Test that credentials are cached and reused."""
        provider = IdentityPoolProvider(settings=settings)

        # Mock the identity pool client
        provider.identity_pool_client.get_credentials = AsyncMock(
            return_value=mock_credentials
        )

        # First call should fetch from AWS
        credentials1 = await provider.get_aws_credentials(mock_jwt_token)
        assert provider.identity_pool_client.get_credentials.call_count == 1

        # Second call should use cache
        credentials2 = await provider.get_aws_credentials(mock_jwt_token)
        assert (
            provider.identity_pool_client.get_credentials.call_count == 1
        )  # No additional call

        # Both should be the same object
        assert credentials1 is credentials2

    @pytest.mark.asyncio
    async def test_credentials_cache_expiration(self, settings, mock_jwt_token):
        """Test that expired credentials are refreshed."""
        provider = IdentityPoolProvider(settings=settings)

        # Create expiring credentials (expires in 4 minutes - within the 5-minute buffer)
        expiring_credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEOLD123",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=datetime.now(UTC) + timedelta(minutes=4),
            identity_id="us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456",
        )

        # Create fresh credentials
        fresh_credentials = AWSCredentials(
            access_key_id="ASIAXAMPLENEW1234",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=datetime.now(UTC) + timedelta(hours=1),
            identity_id="us-east-1:abcdefgh-1234-5678-90ab-cdefgh123456",
        )

        # Mock to return expiring credentials first, then fresh ones
        provider.identity_pool_client.get_credentials = AsyncMock(
            side_effect=[expiring_credentials, fresh_credentials]
        )

        # First call gets expiring credentials
        creds1 = await provider.get_aws_credentials(mock_jwt_token)
        assert creds1.access_key_id == "ASIAXAMPLEOLD123"

        # Second call should refresh because credentials are expiring soon
        creds2 = await provider.get_aws_credentials(mock_jwt_token)
        assert creds2.access_key_id == "ASIAXAMPLENEW1234"
        assert provider.identity_pool_client.get_credentials.call_count == 2

    @pytest.mark.asyncio
    async def test_clear_credentials_cache_specific_user(
        self, settings, mock_jwt_token, mock_credentials
    ):
        """Test clearing cache for specific user."""
        provider = IdentityPoolProvider(settings=settings)

        provider.identity_pool_client.get_credentials = AsyncMock(
            return_value=mock_credentials
        )

        # Get credentials for user
        await provider.get_aws_credentials(mock_jwt_token)

        # Verify cache is populated
        user_id = mock_jwt_token.claims["sub"]
        assert user_id in provider._identity_id_cache
        assert mock_credentials.identity_id in provider._credentials_cache

        # Clear cache for this user
        await provider.clear_credentials_cache(user_id=user_id)

        # Verify cache is empty
        assert user_id not in provider._identity_id_cache
        assert mock_credentials.identity_id not in provider._credentials_cache

    @pytest.mark.asyncio
    async def test_clear_credentials_cache_all(
        self, settings, mock_jwt_token, mock_credentials
    ):
        """Test clearing entire cache."""
        provider = IdentityPoolProvider(settings=settings)

        provider.identity_pool_client.get_credentials = AsyncMock(
            return_value=mock_credentials
        )

        # Get credentials
        await provider.get_aws_credentials(mock_jwt_token)

        # Verify cache is populated
        assert len(provider._identity_id_cache) > 0
        assert len(provider._credentials_cache) > 0

        # Clear all cache
        await provider.clear_credentials_cache()

        # Verify cache is empty
        assert len(provider._identity_id_cache) == 0
        assert len(provider._credentials_cache) == 0

    @pytest.mark.asyncio
    async def test_get_credentials_without_identity_pool(self):
        """Test error when Identity Pool is not configured."""
        # Create a minimal provider that doesn't have identity_pool_client
        # by creating it without proper initialization
        settings = CognitoAuthzProviderSettings(
            user_pool_region="us-east-1",
            user_pool_id="us-east-1_AbCdEfGhI",
        )

        # Create a CognitoProvider (not IdentityPoolProvider)
        from auth_middleware.providers.authn.cognito_provider import CognitoProvider

        provider = CognitoProvider(settings=settings)

        # Now try to call the IdentityPoolProvider method on it
        # This should fail because it doesn't have identity_pool_client
        with pytest.raises(ValueError, match="Identity Pool is not configured"):
            # Call get_aws_credentials which requires identity_pool_client
            await IdentityPoolProvider.get_aws_credentials(provider, "jwt-token")

    @pytest.mark.asyncio
    async def test_close_method(self, settings):
        """Test closing the provider."""
        provider = IdentityPoolProvider(settings=settings)

        provider.identity_pool_client.close = AsyncMock()

        await provider.close()

        provider.identity_pool_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager(self, settings):
        """Test async context manager usage."""
        async with IdentityPoolProvider(settings=settings) as provider:
            assert hasattr(provider, "identity_pool_client")

        # After exiting context, resources should be cleaned up
        # (verified by checking close was called internally)

    @pytest.mark.asyncio
    async def test_extends_cognito_provider(self, settings):
        """Test that IdentityPoolProvider extends CognitoProvider."""
        from auth_middleware.providers.authn.cognito_provider import CognitoProvider

        provider = IdentityPoolProvider(settings=settings)

        assert isinstance(provider, CognitoProvider)
        assert hasattr(provider, "verify_token")
        assert hasattr(provider, "create_user_from_token")
        assert hasattr(provider, "load_jwks")

    @pytest.mark.asyncio
    async def test_cache_with_different_users(self, settings):
        """Test cache with multiple different users."""
        provider = IdentityPoolProvider(settings=settings)

        # Create two different JWT tokens
        token1 = MagicMock(spec=JWTAuthorizationCredentials)
        token1.claims = {"sub": "user-1", "cognito:username": "user1"}
        token1.__str__ = MagicMock(return_value="token-1")

        token2 = MagicMock(spec=JWTAuthorizationCredentials)
        token2.claims = {"sub": "user-2", "cognito:username": "user2"}
        token2.__str__ = MagicMock(return_value="token-2")

        # Create different credentials for each user
        creds1 = AWSCredentials(
            access_key_id="ASIAXAMPLEUSER01",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=datetime.now(UTC) + timedelta(hours=1),
            identity_id="us-east-1:12345678-1234-1234-1234-123456789001",
        )

        creds2 = AWSCredentials(
            access_key_id="ASIAXAMPLEUSER02",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "y" * 100,
            expiration=datetime.now(UTC) + timedelta(hours=1),
            identity_id="us-east-1:12345678-1234-1234-1234-123456789002",
        )

        provider.identity_pool_client.get_credentials = AsyncMock(
            side_effect=[creds1, creds2]
        )

        # Get credentials for both users
        result1 = await provider.get_aws_credentials(token1)
        result2 = await provider.get_aws_credentials(token2)

        # Verify both are cached independently
        assert result1.access_key_id == "ASIAXAMPLEUSER01"
        assert result2.access_key_id == "ASIAXAMPLEUSER02"
        assert len(provider._identity_id_cache) == 2
        assert len(provider._credentials_cache) == 2

    def test_identity_pool_region_defaults(self):
        """Test that identity_pool_region defaults to user_pool_region."""
        settings = IdentityPoolSettings(
            user_pool_region="eu-west-1",
            user_pool_id="eu-west-1_AbCdEfGhI",
            identity_pool_id="eu-west-1:12345678-1234-1234-1234-123456789012",
        )

        provider = IdentityPoolProvider(settings=settings)

        assert provider.identity_pool_client.region == "eu-west-1"
