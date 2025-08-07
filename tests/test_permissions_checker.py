import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException, Request

from auth_middleware.permissions_checker import PermissionsChecker
from auth_middleware.types.user import User


class TestPermissionsChecker:
    """Test the PermissionsChecker class."""

    @pytest.fixture
    def permissions_checker(self):
        """Create a PermissionsChecker instance."""
        return PermissionsChecker(allowed_permissions=["admin", "manager"])

    @pytest.fixture
    def mock_request(self):
        """Create a mock request."""
        request = Mock(spec=Request)
        request.state = Mock()
        return request

    @pytest.fixture
    def mock_user(self):
        """Create a mock user."""
        user = Mock(spec=User)
        # Mock the async permissions property correctly
        async def get_permissions():
            return ["admin"]
        user.permissions = get_permissions()
        return user

    def test_permissions_checker_init(self):
        """Test PermissionsChecker initialization."""
        allowed_permissions = ["admin", "user", "guest"]
        checker = PermissionsChecker(allowed_permissions=allowed_permissions)
        
        # Access private attribute for testing
        assert checker._PermissionsChecker__allowed_permissions == allowed_permissions

    @pytest.mark.asyncio
    async def test_permissions_checker_disabled_middleware(self, permissions_checker, mock_request):
        """Test that checker returns early when middleware is disabled."""
        with patch('auth_middleware.permissions_checker.settings') as mock_settings:
            mock_settings.AUTH_MIDDLEWARE_DISABLED = True
            
            # Should return None without checking anything
            result = await permissions_checker(mock_request)
            assert result is None

    @pytest.mark.asyncio
    async def test_permissions_checker_no_current_user(self, permissions_checker, mock_request):
        """Test that checker raises 401 when no current user."""
        with patch('auth_middleware.permissions_checker.settings') as mock_settings:
            mock_settings.AUTH_MIDDLEWARE_DISABLED = False
            mock_request.state.current_user = None
            
            with pytest.raises(HTTPException) as exc_info:
                await permissions_checker(mock_request)
            
            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Authentication required"

    @pytest.mark.asyncio
    async def test_permissions_checker_missing_current_user_attribute(self, permissions_checker, mock_request):
        """Test that checker raises 401 when current_user attribute is missing."""
        with patch('auth_middleware.permissions_checker.settings') as mock_settings:
            mock_settings.AUTH_MIDDLEWARE_DISABLED = False
            # Remove the current_user attribute
            delattr(mock_request.state, 'current_user')
            
            with pytest.raises(HTTPException) as exc_info:
                await permissions_checker(mock_request)
            
            assert exc_info.value.status_code == 401
            assert exc_info.value.detail == "Authentication required"

    @pytest.mark.asyncio
    async def test_permissions_checker_valid_permissions(self, permissions_checker, mock_request, mock_user):
        """Test that checker passes with valid permissions."""
        with patch('auth_middleware.permissions_checker.settings') as mock_settings:
            mock_settings.AUTH_MIDDLEWARE_DISABLED = False
            mock_request.state.current_user = mock_user
            
            async def get_permissions():
                return ["admin"]
            mock_user.permissions = get_permissions()
            
            # Should pass without raising an exception
            result = await permissions_checker(mock_request)
            assert result is None

    @pytest.mark.asyncio
    async def test_permissions_checker_invalid_permissions(self, permissions_checker, mock_request, mock_user):
        """Test that checker raises 403 with invalid permissions."""
        with patch('auth_middleware.permissions_checker.settings') as mock_settings:
            mock_settings.AUTH_MIDDLEWARE_DISABLED = False
            mock_request.state.current_user = mock_user
            
            async def get_permissions():
                return ["guest"]
            mock_user.permissions = get_permissions()
            
            with pytest.raises(HTTPException) as exc_info:
                await permissions_checker(mock_request)
            
            assert exc_info.value.status_code == 403
            assert exc_info.value.detail == "Operation not allowed"

    @pytest.mark.asyncio
    async def test_permissions_checker_multiple_valid_permissions(self, permissions_checker, mock_request, mock_user):
        """Test that checker passes with multiple permissions where one is valid."""
        with patch('auth_middleware.permissions_checker.settings') as mock_settings:
            mock_settings.AUTH_MIDDLEWARE_DISABLED = False
            mock_request.state.current_user = mock_user
            
            async def get_permissions():
                return ["guest", "manager", "other"]
            mock_user.permissions = get_permissions()
            
            # Should pass because "manager" is in allowed permissions
            result = await permissions_checker(mock_request)
            assert result is None

    @pytest.mark.asyncio
    async def test_permissions_checker_none_permissions(self, permissions_checker, mock_request, mock_user):
        """Test that checker handles None permissions correctly."""
        with patch('auth_middleware.permissions_checker.settings') as mock_settings:
            mock_settings.AUTH_MIDDLEWARE_DISABLED = False
            mock_request.state.current_user = mock_user
            
            async def get_permissions():
                return None
            mock_user.permissions = get_permissions()
            
            # Should pass when permissions is None (the logic in the actual code)
            result = await permissions_checker(mock_request)
            assert result is None

    @pytest.mark.asyncio
    async def test_permissions_checker_empty_permissions(self, permissions_checker, mock_request, mock_user):
        """Test that checker raises 403 with empty permissions."""
        with patch('auth_middleware.permissions_checker.settings') as mock_settings:
            mock_settings.AUTH_MIDDLEWARE_DISABLED = False
            mock_request.state.current_user = mock_user
            
            async def get_permissions():
                return []
            mock_user.permissions = get_permissions()
            
            with pytest.raises(HTTPException) as exc_info:
                await permissions_checker(mock_request)
            
            assert exc_info.value.status_code == 403
            assert exc_info.value.detail == "Operation not allowed"

    @pytest.mark.asyncio
    async def test_permissions_checker_logging(self, permissions_checker, mock_request, mock_user):
        """Test that checker logs debug information."""
        with patch('auth_middleware.permissions_checker.settings') as mock_settings:
            with patch('auth_middleware.permissions_checker.logger') as mock_logger:
                mock_settings.AUTH_MIDDLEWARE_DISABLED = False
                mock_request.state.current_user = mock_user
                
                async def get_permissions():
                    return ["unauthorized"]
                mock_user.permissions = get_permissions()
                
                with pytest.raises(HTTPException):
                    await permissions_checker(mock_request)
                
                # Verify that debug logging was called
                mock_logger.debug.assert_called_once()

    def test_permissions_checker_different_allowed_permissions(self):
        """Test PermissionsChecker with different allowed permissions."""
        checker1 = PermissionsChecker(["read", "write"])
        checker2 = PermissionsChecker(["execute", "delete"])
        
        assert checker1._PermissionsChecker__allowed_permissions == ["read", "write"]
        assert checker2._PermissionsChecker__allowed_permissions == ["execute", "delete"]