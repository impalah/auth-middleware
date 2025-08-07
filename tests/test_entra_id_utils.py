import pytest
from urllib.parse import unquote

from auth_middleware.providers.entra_id.utils import get_login_url, get_logout_url


class TestEntraIdUtils:
    """Test the EntraID utility functions."""

    def test_get_login_url_with_all_parameters(self):
        """Test get_login_url with all parameters provided."""
        tenant_id = "test-tenant-id"
        client_id = "test-client-id"
        redirect_uri = "https://example.com/callback"
        state = "custom-state"
        nonce = "custom-nonce"
        
        result = get_login_url(
            tenant_id=tenant_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce
        )
        
        assert tenant_id in result
        assert client_id in result
        assert "https%3A%2F%2Fexample.com%2Fcallback" in result  # URL encoded redirect_uri with proper encoding
        assert state in result
        assert nonce in result
        assert "login.microsoftonline.com" in result
        assert "oauth2/v2.0/authorize" in result

    def test_get_login_url_with_defaults(self):
        """Test get_login_url with default state and nonce."""
        tenant_id = "test-tenant-id"
        client_id = "test-client-id"
        redirect_uri = "https://example.com/callback"
        
        result = get_login_url(
            tenant_id=tenant_id,
            client_id=client_id,
            redirect_uri=redirect_uri
        )
        
        assert tenant_id in result
        assert client_id in result
        assert "1234567890" in result  # default state
        assert "9876543210" in result  # default nonce

    def test_get_login_url_with_custom_state_only(self):
        """Test get_login_url with custom state but default nonce."""
        tenant_id = "test-tenant-id"
        client_id = "test-client-id"
        redirect_uri = "https://example.com/callback"
        state = "my-custom-state"
        
        result = get_login_url(
            tenant_id=tenant_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state
        )
        
        assert state in result
        assert "9876543210" in result  # default nonce

    def test_get_login_url_with_custom_nonce_only(self):
        """Test get_login_url with custom nonce but default state."""
        tenant_id = "test-tenant-id"
        client_id = "test-client-id"
        redirect_uri = "https://example.com/callback"
        nonce = "my-custom-nonce"
        
        result = get_login_url(
            tenant_id=tenant_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            nonce=nonce
        )
        
        assert "1234567890" in result  # default state
        assert nonce in result

    def test_get_login_url_redirect_uri_encoding(self):
        """Test that redirect_uri is properly URL encoded."""
        tenant_id = "test-tenant"
        client_id = "test-client"
        redirect_uri = "https://example.com/callback?param=value&other=test"
        
        result = get_login_url(
            tenant_id=tenant_id,
            client_id=client_id,
            redirect_uri=redirect_uri
        )
        
        # The redirect_uri should be URL encoded correctly
        assert "https%3A%2F%2Fexample.com%2Fcallback%3Fparam%3Dvalue%26other%3Dtest" in result

    def test_get_login_url_contains_required_parameters(self):
        """Test that the login URL contains all required OAuth parameters."""
        result = get_login_url(
            tenant_id="tenant",
            client_id="client",
            redirect_uri="https://example.com"
        )
        
        # Check for required OAuth2 parameters
        assert "response_type=id_token%20token" in result
        assert "scope=openid%20email%20profile" in result
        assert "client_id=" in result
        assert "redirect_uri=" in result
        assert "state=" in result
        assert "nonce=" in result

    def test_get_logout_url(self):
        """Test get_logout_url function."""
        tenant_id = "test-tenant-id"
        client_id = "test-client-id"
        redirect_uri = "https://example.com/logout"
        
        result = get_logout_url(
            tenant_id=tenant_id,
            client_id=client_id,
            redirect_uri=redirect_uri
        )
        
        # Currently returns empty string as per implementation
        assert result == ""

    def test_get_logout_url_with_different_parameters(self):
        """Test get_logout_url with various parameters."""
        result1 = get_logout_url("tenant1", "client1", "https://example1.com")
        result2 = get_logout_url("tenant2", "client2", "https://example2.com")
        
        # Both should return empty string as per current implementation
        assert result1 == ""
        assert result2 == ""
