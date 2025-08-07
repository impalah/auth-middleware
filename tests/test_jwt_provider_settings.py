"""
Comprehensive tests for auth_middleware.providers.authn.jwt_provider_settings module.
"""

import os
from unittest.mock import patch

from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings


class TestJWTProviderSettings:
    """Test cases for JWTProviderSettings class."""

    def test_jwt_provider_settings_default_values(self):
        """Test JWTProviderSettings with default values."""
        settings = JWTProviderSettings()

        assert settings.jwt_secret_key is None
        assert settings.jwt_algorithm == "HS256"
        assert settings.jwt_token_verification_disabled is False

    def test_jwt_provider_settings_explicit_values(self):
        """Test JWTProviderSettings with explicit values."""
        settings = JWTProviderSettings(
            jwt_secret_key="test-secret-key",
            jwt_algorithm="RS256",
            jwt_token_verification_disabled=True,
        )

        assert settings.jwt_secret_key == "test-secret-key"
        assert settings.jwt_algorithm == "RS256"
        assert settings.jwt_token_verification_disabled is True

    def test_jwt_provider_settings_partial_values(self):
        """Test JWTProviderSettings with partial explicit values."""
        settings = JWTProviderSettings(jwt_secret_key="custom-secret")

        assert settings.jwt_secret_key == "custom-secret"
        assert settings.jwt_algorithm == "HS256"  # Default
        assert settings.jwt_token_verification_disabled is False  # Default

    def test_jwt_provider_settings_algorithm_variations(self):
        """Test JWTProviderSettings with different algorithm values."""
        algorithms = [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
        ]

        for algorithm in algorithms:
            settings = JWTProviderSettings(jwt_algorithm=algorithm)
            assert settings.jwt_algorithm == algorithm

    def test_jwt_provider_settings_secret_key_variations(self):
        """Test JWTProviderSettings with different secret key formats."""
        secret_keys = [
            "simple-key",
            "very-long-secret-key-with-many-characters-123456789",
            "key-with-special-chars!@#$%^&*()",
            "base64-like-key-ABCD1234",
            "",  # Empty string
        ]

        for secret_key in secret_keys:
            settings = JWTProviderSettings(jwt_secret_key=secret_key)
            assert settings.jwt_secret_key == secret_key

    def test_jwt_provider_settings_verification_disabled_variations(self):
        """Test JWTProviderSettings with different verification disabled values."""
        # Test with True
        settings_true = JWTProviderSettings(jwt_token_verification_disabled=True)
        assert settings_true.jwt_token_verification_disabled is True

        # Test with False
        settings_false = JWTProviderSettings(jwt_token_verification_disabled=False)
        assert settings_false.jwt_token_verification_disabled is False

    @patch.dict(
        os.environ,
        {
            "JWT_SECRET_KEY": "env-secret-key",
            "JWT_ALGORITHM": "RS256",
            "JWT_TOKEN_VERIFICATION_DISABLED": "true",
        },
    )
    def test_jwt_provider_settings_from_environment(self):
        """Test JWTProviderSettings loading from environment variables."""
        settings = JWTProviderSettings()

        assert settings.jwt_secret_key == "env-secret-key"
        assert settings.jwt_algorithm == "RS256"
        assert settings.jwt_token_verification_disabled is True

    @patch.dict(os.environ, {"JWT_SECRET_KEY": "env-secret", "JWT_ALGORITHM": "ES256"})
    def test_jwt_provider_settings_environment_override(self):
        """Test JWTProviderSettings environment variables override explicit values."""
        # Explicit values should override environment when provided
        settings = JWTProviderSettings(
            jwt_secret_key="explicit-secret", jwt_algorithm="HS256"
        )

        assert settings.jwt_secret_key == "explicit-secret"
        assert settings.jwt_algorithm == "HS256"

    @patch.dict(os.environ, {"JWT_TOKEN_VERIFICATION_DISABLED": "false"})
    def test_jwt_provider_settings_boolean_environment_false(self):
        """Test JWTProviderSettings boolean environment variable set to false."""
        settings = JWTProviderSettings()

        assert settings.jwt_token_verification_disabled is False

    @patch.dict(os.environ, {"JWT_TOKEN_VERIFICATION_DISABLED": "1"})
    def test_jwt_provider_settings_boolean_environment_truthy(self):
        """Test JWTProviderSettings boolean environment variable with truthy value."""
        settings = JWTProviderSettings()

        assert settings.jwt_token_verification_disabled is True

    @patch.dict(os.environ, {"JWT_TOKEN_VERIFICATION_DISABLED": "0"})
    def test_jwt_provider_settings_boolean_environment_falsy(self):
        """Test JWTProviderSettings boolean environment variable with falsy value."""
        settings = JWTProviderSettings()

        assert settings.jwt_token_verification_disabled is False

    def test_jwt_provider_settings_dict_conversion(self):
        """Test JWTProviderSettings conversion to dictionary."""
        settings = JWTProviderSettings(
            jwt_secret_key="test-key",
            jwt_algorithm="RS256",
            jwt_token_verification_disabled=True,
        )

        settings_dict = settings.model_dump()

        assert settings_dict["jwt_secret_key"] == "test-key"
        assert settings_dict["jwt_algorithm"] == "RS256"
        assert settings_dict["jwt_token_verification_disabled"] is True

    def test_jwt_provider_settings_json_serialization(self):
        """Test JWTProviderSettings JSON serialization."""
        settings = JWTProviderSettings(
            jwt_secret_key="test-key",
            jwt_algorithm="RS256",
            jwt_token_verification_disabled=True,
        )

        settings_json = settings.model_dump_json()

        assert '"jwt_secret_key":"test-key"' in settings_json
        assert '"jwt_algorithm":"RS256"' in settings_json
        assert '"jwt_token_verification_disabled":true' in settings_json

    def test_jwt_provider_settings_model_validation(self):
        """Test JWTProviderSettings model validation."""
        # Valid settings should not raise
        valid_settings = JWTProviderSettings(
            jwt_secret_key="valid-key",
            jwt_algorithm="HS256",
            jwt_token_verification_disabled=False,
        )

        assert valid_settings is not None

    def test_jwt_provider_settings_copy_and_update(self):
        """Test JWTProviderSettings copy and update functionality."""
        original_settings = JWTProviderSettings(
            jwt_secret_key="original-key",
            jwt_algorithm="HS256",
            jwt_token_verification_disabled=False,
        )

        # Create updated copy
        updated_settings = original_settings.model_copy(
            update={"jwt_algorithm": "RS256", "jwt_token_verification_disabled": True}
        )

        # Original should be unchanged
        assert original_settings.jwt_secret_key == "original-key"
        assert original_settings.jwt_algorithm == "HS256"
        assert original_settings.jwt_token_verification_disabled is False

        # Updated should have new values
        assert updated_settings.jwt_secret_key == "original-key"  # Unchanged
        assert updated_settings.jwt_algorithm == "RS256"  # Updated
        assert updated_settings.jwt_token_verification_disabled is True  # Updated

    def test_jwt_provider_settings_equality(self):
        """Test JWTProviderSettings equality comparison."""
        settings1 = JWTProviderSettings(
            jwt_secret_key="key1",
            jwt_algorithm="HS256",
            jwt_token_verification_disabled=False,
        )

        settings2 = JWTProviderSettings(
            jwt_secret_key="key1",
            jwt_algorithm="HS256",
            jwt_token_verification_disabled=False,
        )

        settings3 = JWTProviderSettings(
            jwt_secret_key="key2",
            jwt_algorithm="HS256",
            jwt_token_verification_disabled=False,
        )

        assert settings1 == settings2
        assert settings1 != settings3

    def test_jwt_provider_settings_field_descriptions(self):
        """Test JWTProviderSettings field descriptions and metadata."""
        # Access the model fields to check descriptions
        fields = JWTProviderSettings.model_fields

        assert "jwt_secret_key" in fields
        assert fields["jwt_secret_key"].description == "Secret key for JWT"

        assert "jwt_algorithm" in fields
        assert fields["jwt_algorithm"].description == "Algorithm used for JWT"

        assert "jwt_token_verification_disabled" in fields
        assert (
            fields["jwt_token_verification_disabled"].description
            == "Disabled JWT verification Token"
        )

    def test_jwt_provider_settings_field_defaults(self):
        """Test JWTProviderSettings field default values."""
        fields = JWTProviderSettings.model_fields

        # jwt_secret_key should have None as default
        assert fields["jwt_secret_key"].default is None

        # jwt_algorithm should have "HS256" as default
        assert fields["jwt_algorithm"].default == "HS256"

        # jwt_token_verification_disabled should have False as default
        assert fields["jwt_token_verification_disabled"].default is False

    @patch.dict(os.environ, {}, clear=True)
    def test_jwt_provider_settings_no_environment(self):
        """Test JWTProviderSettings with no environment variables set."""
        settings = JWTProviderSettings()

        assert settings.jwt_secret_key is None
        assert settings.jwt_algorithm == "HS256"
        assert settings.jwt_token_verification_disabled is False

    def test_jwt_provider_settings_config_class(self):
        """Test JWTProviderSettings Config class settings."""
        config = JWTProviderSettings.model_config

        # Check that environment file configuration is set
        assert "env_file" in config
        assert config["env_file"] == ".env"
        assert config["env_file_encoding"] == "utf-8"

    def test_jwt_provider_settings_none_values(self):
        """Test JWTProviderSettings with explicit None values."""
        settings = JWTProviderSettings(
            jwt_secret_key=None,
            jwt_algorithm=None,
            jwt_token_verification_disabled=None,
        )

        assert settings.jwt_secret_key is None
        assert settings.jwt_algorithm is None
        assert settings.jwt_token_verification_disabled is None

    def test_jwt_provider_settings_type_validation(self):
        """Test JWTProviderSettings with type validation."""
        # String values should work for secret key and algorithm
        settings = JWTProviderSettings(
            jwt_secret_key="string_key", jwt_algorithm="string_algorithm"
        )

        assert isinstance(settings.jwt_secret_key, str)
        assert isinstance(settings.jwt_algorithm, str)

        # Boolean values should work for verification disabled
        settings_bool = JWTProviderSettings(jwt_token_verification_disabled=True)

        assert isinstance(settings_bool.jwt_token_verification_disabled, bool)

    def test_jwt_provider_settings_str_representation(self):
        """Test JWTProviderSettings string representation."""
        settings = JWTProviderSettings(
            jwt_secret_key="test-key",
            jwt_algorithm="HS256",
            jwt_token_verification_disabled=True,
        )

        settings_str = str(settings)

        # String representation should contain field values
        assert "jwt_secret_key" in settings_str
        assert "jwt_algorithm" in settings_str
        assert "jwt_token_verification_disabled" in settings_str

    def test_jwt_provider_settings_hash_consistency(self):
        """Test JWTProviderSettings hash consistency."""
        settings1 = JWTProviderSettings(
            jwt_secret_key="key1",
            jwt_algorithm="HS256",
            jwt_token_verification_disabled=False,
        )

        settings2 = JWTProviderSettings(
            jwt_secret_key="key1",
            jwt_algorithm="HS256",
            jwt_token_verification_disabled=False,
        )

        # Equal objects should have equal hashes
        assert hash(settings1) == hash(settings2)

    @patch.dict(
        os.environ, {"JWT_SECRET_KEY": "env-key", "UNRELATED_VAR": "should-be-ignored"}
    )
    def test_jwt_provider_settings_env_filtering(self):
        """Test JWTProviderSettings only uses relevant environment variables."""
        settings = JWTProviderSettings()

        # Should pick up JWT_SECRET_KEY but ignore UNRELATED_VAR
        assert settings.jwt_secret_key == "env-key"
        assert not hasattr(settings, "unrelated_var")

    def test_jwt_provider_settings_immutability_pattern(self):
        """Test JWTProviderSettings follows immutability patterns."""
        settings = JWTProviderSettings(
            jwt_secret_key="original-key", jwt_algorithm="HS256"
        )

        # Pydantic models are immutable by default when frozen
        # Even if not frozen, we shouldn't modify in place in production code
        # Instead, create new instances with updated values

        new_settings = settings.model_copy(update={"jwt_algorithm": "RS256"})

        assert settings.jwt_algorithm == "HS256"  # Original unchanged
        assert new_settings.jwt_algorithm == "RS256"  # New instance updated
