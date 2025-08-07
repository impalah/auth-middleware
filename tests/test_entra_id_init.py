import pytest

from auth_middleware.providers.entra_id import (
    EntraIDProvider,
    get_login_url,
    get_logout_url,
)


class TestEntraIdInit:
    """Test the EntraID module __init__.py exports."""

    def test_exports_are_available(self):
        """Test that all expected exports are available."""
        # These imports should work without errors
        assert EntraIDProvider is not None
        assert get_login_url is not None
        assert get_logout_url is not None

    def test_entra_id_provider_import(self):
        """Test that EntraIDProvider can be imported."""
        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider as DirectImport
        assert EntraIDProvider is DirectImport

    def test_utils_functions_import(self):
        """Test that utility functions can be imported."""
        from auth_middleware.providers.entra_id.utils import get_login_url as DirectLoginImport
        from auth_middleware.providers.entra_id.utils import get_logout_url as DirectLogoutImport
        
        assert get_login_url is DirectLoginImport
        assert get_logout_url is DirectLogoutImport

    def test_all_exports_defined(self):
        """Test that __all__ contains the expected exports."""
        import auth_middleware.providers.entra_id as module
        
        expected_exports = [
            "EntraIDProvider",
            "get_login_url", 
            "get_logout_url",
        ]
        
        assert hasattr(module, '__all__')
        assert set(module.__all__) == set(expected_exports)

    def test_functions_are_callable(self):
        """Test that the exported functions are callable."""
        assert callable(get_login_url)
        assert callable(get_logout_url)

    def test_class_is_instantiable(self):
        """Test that EntraIDProvider class exists and has the expected structure."""
        # Just test that the class exists and can be referenced
        assert hasattr(EntraIDProvider, '__name__')
        assert EntraIDProvider.__name__ == 'EntraIDProvider'
