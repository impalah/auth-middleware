import os
import pytest
import sys
from unittest.mock import patch, Mock

from auth_middleware.providers.entra_id.settings import ModuleSettings, settings


class TestModuleSettings:
    """Test the EntraID ModuleSettings class."""

    def test_module_settings_defaults(self):
        """Test that ModuleSettings has correct default values."""
        test_settings = ModuleSettings()
        
        assert test_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID is None
        assert test_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID is None
        assert test_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_JWKS_URL_TEMPLATE == (
            "https://login.microsoftonline.com/{}/v2.0/.well-known/openid-configuration"
        )

    def test_module_settings_from_environment(self):
        """Test that ModuleSettings reads values from environment variables."""
        env_vars = {
            "AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID": "test-tenant-id",
            "AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID": "test-audience-id",
            "AUTH_PROVIDER_AZURE_ENTRA_ID_JWKS_URL_TEMPLATE": "https://custom.url/{}/jwks.json"
        }
        
        with patch.dict(os.environ, env_vars, clear=False):
            # Remove modules from cache to force re-import
            modules_to_remove = [
                'auth_middleware.providers.entra_id.settings',
            ]
            for module in modules_to_remove:
                if module in sys.modules:
                    del sys.modules[module]
            
            # Import the module fresh with new environment
            import auth_middleware.providers.entra_id.settings as entra_id_settings_module
            
            test_settings = entra_id_settings_module.ModuleSettings()
            
            assert test_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID == "test-tenant-id"
            assert test_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID == "test-audience-id"
            assert test_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_JWKS_URL_TEMPLATE == "https://custom.url/{}/jwks.json"

    def test_settings_singleton_instance(self):
        """Test that the settings instance is available."""
        assert settings is not None
        assert isinstance(settings, ModuleSettings)

    def test_module_settings_inheritance(self):
        """Test that ModuleSettings inherits from Settings."""
        from auth_middleware.settings import Settings
        
        test_settings = ModuleSettings()
        assert isinstance(test_settings, Settings)
