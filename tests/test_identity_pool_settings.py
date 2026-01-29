"""Tests for Identity Pool Settings."""

import pytest

from auth_middleware.providers.authn.identity_pool_settings import IdentityPoolSettings


class TestIdentityPoolSettings:
    """Test suite for IdentityPoolSettings configuration."""

    def test_basic_initialization(self):
        """Test basic settings initialization with all required fields."""
        settings = IdentityPoolSettings(
            user_pool_id="us-east-1_abcd1234",
            user_pool_region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        assert (
            settings.identity_pool_id
            == "us-east-1:12345678-1234-1234-1234-123456789012"
        )
        assert settings.identity_pool_region == "us-east-1"
        assert settings.enable_aws_credentials is True
        assert settings.credentials_duration_seconds == 3600

    def test_identity_pool_region_defaults_to_user_pool_region(self):
        """Test that identity_pool_region defaults to user_pool_region."""
        settings = IdentityPoolSettings(
            user_pool_id="us-west-2_xyz789",
            user_pool_region="us-west-2",
            identity_pool_id="us-west-2:12345678-1234-1234-1234-123456789012",
        )

        assert settings.identity_pool_region == "us-west-2"

    def test_explicit_identity_pool_region(self):
        """Test setting explicit identity_pool_region different from user pool."""
        settings = IdentityPoolSettings(
            user_pool_id="us-east-1_abcd1234",
            user_pool_region="us-east-1",
            identity_pool_id="us-west-2:12345678-1234-1234-1234-123456789012",
            identity_pool_region="us-west-2",
        )

        assert settings.user_pool_region == "us-east-1"
        assert settings.identity_pool_region == "us-west-2"

    def test_disable_aws_credentials(self):
        """Test disabling AWS credentials exchange."""
        settings = IdentityPoolSettings(
            user_pool_id="us-east-1_abcd1234",
            user_pool_region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            enable_aws_credentials=False,
        )

        assert settings.enable_aws_credentials is False

    def test_custom_credentials_duration(self):
        """Test setting custom credentials duration."""
        settings = IdentityPoolSettings(
            user_pool_id="us-east-1_abcd1234",
            user_pool_region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            credentials_duration_seconds=1800,  # 30 minutes
        )

        assert settings.credentials_duration_seconds == 1800

    def test_maximum_credentials_duration(self):
        """Test maximum allowed credentials duration (1 hour)."""
        settings = IdentityPoolSettings(
            user_pool_id="us-east-1_abcd1234",
            user_pool_region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            credentials_duration_seconds=3600,
        )

        assert settings.credentials_duration_seconds == 3600

    def test_credentials_duration_exceeds_maximum(self):
        """Test validation error when credentials duration exceeds 1 hour."""
        with pytest.raises(ValueError, match="cannot exceed 3600"):
            IdentityPoolSettings(
                user_pool_id="us-east-1_abcd1234",
                user_pool_region="us-east-1",
                identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
                credentials_duration_seconds=7200,  # 2 hours - too long
            )

    def test_credentials_duration_below_minimum(self):
        """Test validation error when credentials duration is too short."""
        with pytest.raises(ValueError, match="must be at least 900"):
            IdentityPoolSettings(
                user_pool_id="us-east-1_abcd1234",
                user_pool_region="us-east-1",
                identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
                credentials_duration_seconds=600,  # 10 minutes - too short
            )

    def test_minimum_credentials_duration(self):
        """Test minimum allowed credentials duration (15 minutes)."""
        settings = IdentityPoolSettings(
            user_pool_id="us-east-1_abcd1234",
            user_pool_region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            credentials_duration_seconds=900,  # 15 minutes
        )

        assert settings.credentials_duration_seconds == 900

    def test_inherits_cognito_provider_settings(self):
        """Test that it inherits all cognito provider settings."""
        settings = IdentityPoolSettings(
            user_pool_id="us-east-1_abcd1234",
            user_pool_region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            jwt_token_verification_disabled=True,
            jwks_cache_interval=30,
        )

        assert settings.jwt_token_verification_disabled is True
        assert settings.jwks_cache_interval == 30

    def test_identity_pool_format_validation(self):
        """Test various identity pool ID formats are accepted."""
        # Valid formats
        valid_ids = [
            "us-east-1:12345678-1234-1234-1234-123456789012",
            "eu-west-1:abcdefgh-1234-5678-90ab-cdefgh123456",
            "ap-northeast-1:00000000-0000-0000-0000-000000000000",
        ]

        for pool_id in valid_ids:
            settings = IdentityPoolSettings(
                user_pool_id="us-east-1_test",
                user_pool_region="us-east-1",
                identity_pool_id=pool_id,
            )
            assert settings.identity_pool_id == pool_id

    def test_multiple_regions(self):
        """Test configuration with different regions for user pool and identity pool."""
        settings = IdentityPoolSettings(
            user_pool_id="us-east-1_abcd1234",
            user_pool_region="us-east-1",
            identity_pool_id="eu-west-1:12345678-1234-1234-1234-123456789012",
            identity_pool_region="eu-west-1",
        )

        assert settings.user_pool_region == "us-east-1"
        assert settings.identity_pool_region == "eu-west-1"
