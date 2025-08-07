import os
import pytest
import importlib
import sys
from unittest.mock import patch, Mock

from auth_middleware.providers.authn.cognito_settings import CognitoSettings, settings


class TestCognitoSettings:
    """Test the CognitoSettings class."""

    def test_cognito_settings_defaults(self):
        """Test that CognitoSettings has correct default values."""
        test_settings = CognitoSettings()
        
        assert test_settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_ID is None
        assert test_settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_REGION is None
        assert test_settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_ID is None
        assert test_settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_SECRET is None
        assert test_settings.AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED is False
        assert test_settings.AUTH_PROVIDER_AWS_COGNITO_JWKS_URL_TEMPLATE == (
            "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json"
        )

    def test_cognito_settings_from_environment(self):
        """Test that CognitoSettings reads values from environment variables."""
        # Set environment variables before importing the module
        env_vars = {
            "AUTH_PROVIDER_AWS_COGNITO_USER_POOL_ID": "us-east-1_TestPool",
            "AUTH_PROVIDER_AWS_COGNITO_USER_POOL_REGION": "us-east-1",
            "AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_ID": "test_client_id",
            "AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_SECRET": "test_secret",
            "AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED": "true",
            "AUTH_PROVIDER_AWS_COGNITO_JWKS_URL_TEMPLATE": "https://custom.url/{}/{}/jwks.json"
        }
        
        with patch.dict(os.environ, env_vars, clear=False):
            # Remove modules from cache to force re-import
            modules_to_remove = [
                'auth_middleware.providers.authn.cognito_settings',
            ]
            for module in modules_to_remove:
                if module in sys.modules:
                    del sys.modules[module]
            
            # Import the module fresh with new environment
            import auth_middleware.providers.authn.cognito_settings as cognito_settings_module
            
            # Create a fresh settings instance
            test_settings = cognito_settings_module.CognitoSettings()
            
            assert test_settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_ID == "us-east-1_TestPool"
            assert test_settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_REGION == "us-east-1"
            assert test_settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_ID == "test_client_id"
            assert test_settings.AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_SECRET == "test_secret"
            assert test_settings.AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED is True
            assert test_settings.AUTH_PROVIDER_AWS_COGNITO_JWKS_URL_TEMPLATE == "https://custom.url/{}/{}/jwks.json"

    def test_settings_singleton_instance(self):
        """Test that the settings instance is available."""
        assert settings is not None
        assert isinstance(settings, CognitoSettings)

    def test_cognito_settings_inheritance(self):
        """Test that CognitoSettings inherits from Settings."""
        from auth_middleware.settings import Settings
        
        test_settings = CognitoSettings()
        assert isinstance(test_settings, Settings)

    @patch.dict(os.environ, {
        "AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED": "false"
    }, clear=False)
    def test_boolean_casting(self):
        """Test that boolean environment variables are cast correctly."""
        # Remove modules from cache to force re-import
        modules_to_remove = [
            'auth_middleware.providers.authn.cognito_settings',
        ]
        for module in modules_to_remove:
            if module in sys.modules:
                del sys.modules[module]
        
        # Import the module fresh with new environment
        import auth_middleware.providers.authn.cognito_settings as cognito_settings_module
        
        test_settings = cognito_settings_module.CognitoSettings()
        assert test_settings.AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED is False

    def test_boolean_casting_truthy(self):
        """Test that truthy values are cast to True."""
        env_vars = {
            "AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED": "1"
        }
        
        with patch.dict(os.environ, env_vars, clear=False):
            # Remove modules from cache to force re-import
            modules_to_remove = [
                'auth_middleware.providers.authn.cognito_settings',
            ]
            for module in modules_to_remove:
                if module in sys.modules:
                    del sys.modules[module]
            
            # Import the module fresh with new environment
            import auth_middleware.providers.authn.cognito_settings as cognito_settings_module
            
            test_settings = cognito_settings_module.CognitoSettings()
            assert test_settings.AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED is True
