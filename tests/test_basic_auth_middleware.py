import base64
import hashlib
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request, status
from starlette.datastructures import Headers, State
from starlette.responses import JSONResponse

from auth_middleware.basic_auth_middleware import BasicAuthMiddleware
from auth_middleware.exceptions.invalid_authorization_exception import (
    InvalidAuthorizationException,
)
from auth_middleware.exceptions.invalid_credentials_exception import (
    InvalidCredentialsException,
)
from auth_middleware.repository.credentials_repository import CredentialsRepository
from auth_middleware.types.user import User
from auth_middleware.types.user_credentials import UserCredentials


class TestBasicAuthMiddleware:
    """Test cases for the BasicAuthMiddleware class."""

    @pytest.fixture
    def mock_credentials_repository(self):
        """Create a mock credentials repository."""
        return Mock(spec=CredentialsRepository)

    @pytest.fixture
    def mock_app(self):
        """Create a mock ASGI app."""
        async def app(scope, receive, send):
            pass
        return app

    @pytest.fixture
    def basic_auth_middleware(self, mock_credentials_repository, mock_app):
        """Create a BasicAuthMiddleware instance with mocked repository."""
        return BasicAuthMiddleware(
            app=mock_app,
            credentials_repository=mock_credentials_repository
        )

    @pytest.fixture
    def mock_request(self):
        """Create a mock request."""
        request = Mock(spec=Request)
        request.state = State()
        request.headers = Headers({})
        return request

    @pytest.fixture
    def valid_credentials(self):
        """Provide valid base64-encoded credentials."""
        username = "testuser"
        password = "testpass"
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode("ascii")
        return username, password, encoded

    @pytest.fixture
    def user_credentials(self):
        """Provide UserCredentials for testing."""
        hashed_password = hashlib.sha256("testpass".encode()).hexdigest()
        return UserCredentials(
            id="testuser",  # Use username as id to match the lookup
            name="testuser",
            hashed_password=hashed_password,
            groups=["admin", "user"]
        )

    def test_init_with_credentials_repository(self, mock_credentials_repository, mock_app):
        """Test middleware initialization with credentials repository."""
        middleware = BasicAuthMiddleware(
            app=mock_app,
            credentials_repository=mock_credentials_repository
        )
        
        assert middleware._credentials_repository is mock_credentials_repository

    @pytest.mark.asyncio
    async def test_dispatch_success(self, basic_auth_middleware, mock_request, valid_credentials, user_credentials):
        """Test successful request dispatch with valid credentials."""
        username, password, encoded = valid_credentials
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        # Setup mocks - use the correct method name
        basic_auth_middleware._credentials_repository.get_by_id = AsyncMock(return_value=user_credentials)
        
        call_next = AsyncMock(return_value=JSONResponse({"message": "success"}))
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            response = await basic_auth_middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        assert hasattr(mock_request.state, "current_user")
        assert mock_request.state.current_user.id == "testuser"

    @pytest.mark.asyncio
    async def test_dispatch_invalid_authorization_exception(self, basic_auth_middleware, mock_request):
        """Test dispatch handling of InvalidAuthorizationException."""
        mock_request.headers = Headers({"authorization": "Basic invalid"})
        
        call_next = AsyncMock()
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with patch.object(basic_auth_middleware, "get_current_user", side_effect=InvalidAuthorizationException(status_code=403, detail="Test error")):
                response = await basic_auth_middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 401
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_general_exception(self, basic_auth_middleware, mock_request):
        """Test dispatch handling of general exceptions."""
        mock_request.headers = Headers({"authorization": "Basic invalid"})
        
        call_next = AsyncMock()
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with patch.object(basic_auth_middleware, "get_current_user", side_effect=Exception("Test error")):
                response = await basic_auth_middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 500
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_credentials_middleware_disabled(self, basic_auth_middleware, mock_request):
        """Test get_credentials when middleware is disabled."""
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", True):
            credentials = await basic_auth_middleware.get_credentials(mock_request)
            assert credentials is None

    @pytest.mark.asyncio
    async def test_get_credentials_valid_basic_auth(self, basic_auth_middleware, mock_request, valid_credentials):
        """Test get_credentials with valid Basic auth."""
        username, password, encoded = valid_credentials
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            credentials = await basic_auth_middleware.get_credentials(mock_request)
        
        assert credentials is not None
        assert credentials[0] == username  # username
        assert credentials[1] == password  # password

    @pytest.mark.asyncio
    async def test_get_credentials_no_authorization_header(self, basic_auth_middleware, mock_request):
        """Test get_credentials with no authorization header."""
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(InvalidAuthorizationException):
                await basic_auth_middleware.get_credentials(mock_request)

    @pytest.mark.asyncio
    async def test_get_credentials_wrong_scheme(self, basic_auth_middleware, mock_request):
        """Test get_credentials with wrong authentication scheme."""
        mock_request.headers = Headers({"authorization": "Bearer token123"})
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(InvalidAuthorizationException):
                await basic_auth_middleware.get_credentials(mock_request)

    @pytest.mark.asyncio
    async def test_get_credentials_invalid_base64(self, basic_auth_middleware, mock_request):
        """Test get_credentials with invalid base64 encoding."""
        mock_request.headers = Headers({"authorization": "Basic invalid_base64!"})
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(InvalidCredentialsException):
                await basic_auth_middleware.get_credentials(mock_request)

    @pytest.mark.asyncio
    async def test_get_credentials_missing_password_separator(self, basic_auth_middleware, mock_request):
        """Test get_credentials with missing colon separator."""
        credentials_without_colon = base64.b64encode("usernameonly".encode()).decode("ascii")
        mock_request.headers = Headers({"authorization": f"Basic {credentials_without_colon}"})
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(InvalidCredentialsException):
                await basic_auth_middleware.get_credentials(mock_request)
                await basic_auth_middleware.get_credentials(mock_request)

    @pytest.mark.asyncio
    async def test_get_credentials_empty_credentials(self, basic_auth_middleware, mock_request):
        """Test get_credentials with empty credentials."""
        empty_credentials = base64.b64encode("".encode()).decode("ascii")
        mock_request.headers = Headers({"authorization": f"Basic {empty_credentials}"})
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(InvalidCredentialsException):
                await basic_auth_middleware.get_credentials(mock_request)

    @pytest.mark.asyncio
    async def test_get_current_user_valid_credentials(self, basic_auth_middleware, mock_request, valid_credentials, user_credentials):
        """Test get_current_user with valid credentials."""
        username, password, encoded = valid_credentials
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        # Mock the repository to return user credentials
        basic_auth_middleware._credentials_repository.get_by_id = AsyncMock(return_value=user_credentials)
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            user = await basic_auth_middleware.get_current_user(mock_request)
        
        assert user is not None
        assert user.id == "testuser"
        groups = await user.groups
        assert groups == ["admin", "user"]

    @pytest.mark.asyncio
    async def test_get_current_user_user_not_found(self, basic_auth_middleware, mock_request, valid_credentials):
        """Test get_current_user when user is not found."""
        username, password, encoded = valid_credentials
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        # Mock the repository to return None (user not found)
        basic_auth_middleware._credentials_repository.get_by_id = AsyncMock(return_value=None)
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(InvalidAuthorizationException):  # Use the correct exception
                await basic_auth_middleware.get_current_user(mock_request)

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_password(self, basic_auth_middleware, mock_request, user_credentials):
        """Test get_current_user with invalid password."""
        wrong_password = "wrongpass"
        credentials = f"testuser:{wrong_password}"
        encoded = base64.b64encode(credentials.encode()).decode("ascii")
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        # Mock the repository to return user credentials
        basic_auth_middleware._credentials_repository.get_by_id = AsyncMock(return_value=user_credentials)
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(InvalidAuthorizationException):  # Use the correct exception
                await basic_auth_middleware.get_current_user(mock_request)

    @pytest.mark.asyncio
    async def test_get_current_user_no_credentials(self, basic_auth_middleware, mock_request):
        """Test get_current_user when no credentials are provided."""
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(InvalidAuthorizationException):
                await basic_auth_middleware.get_current_user(mock_request)

    @pytest.mark.asyncio
    async def test_get_current_user_with_groups(self, basic_auth_middleware, mock_request, valid_credentials):
        """Test get_current_user returns user with groups."""
        username, password, encoded = valid_credentials
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        user_credentials = UserCredentials(
            id=username,  # Use username as id
            name=username,
            hashed_password=hashlib.sha256(password.encode()).hexdigest(),
            groups=["admin", "developer", "user"]
        )
        
        basic_auth_middleware._credentials_repository.get_by_id = AsyncMock(return_value=user_credentials)
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            user = await basic_auth_middleware.get_current_user(mock_request)
        
        assert user is not None
        assert user.id == username
        groups = await user.groups
        assert set(groups) == {"admin", "developer", "user"}

    # @pytest.mark.asyncio
    # async def test_password_hashing_verification(self, basic_auth_middleware):
    #     """Test password hashing and verification methods."""
    #     # This test is not valid because the middleware doesn't provide these methods
    #     # password = "mySecurePassword123!"
    #     # hashed = basic_auth_middleware._hash_password(password)
    #     # assert hashed != password
    #     pass

    @pytest.mark.asyncio
    async def test_edge_case_special_characters_in_credentials(self, basic_auth_middleware, mock_request):
        """Test credentials with special characters."""
        username = "user@domain.com"
        password = "pass!@#$%^&*()"
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode("ascii")
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            creds = await basic_auth_middleware.get_credentials(mock_request)
        
        assert creds[0] == username
        assert creds[1] == password

    @pytest.mark.asyncio
    async def test_edge_case_unicode_credentials(self, basic_auth_middleware, mock_request):
        """Test credentials with unicode characters."""
        username = "usuario"
        password = "contraseña"
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            creds = await basic_auth_middleware.get_credentials(mock_request)
        
        assert creds[0] == username
        assert creds[1] == password

    @pytest.mark.asyncio
    async def test_multiple_colons_in_password(self, basic_auth_middleware, mock_request):
        """Test password that contains multiple colons."""
        username = "testuser"
        password = "my:pass:word:with:colons"
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode("ascii")
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            creds = await basic_auth_middleware.get_credentials(mock_request)
        
        assert creds[0] == username
        assert creds[1] == password

    @pytest.mark.asyncio
    async def test_case_insensitive_basic_scheme(self, basic_auth_middleware, mock_request, valid_credentials):
        """Test that Basic scheme is case-insensitive."""
        username, password, encoded = valid_credentials
        mock_request.headers = Headers({"authorization": f"basic {encoded}"})  # lowercase
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            creds = await basic_auth_middleware.get_credentials(mock_request)
        
        assert creds[0] == username
        assert creds[1] == password

    @pytest.mark.asyncio
    async def test_repository_exception_handling(self, basic_auth_middleware, mock_request, valid_credentials):
        """Test handling of repository exceptions."""
        username, password, encoded = valid_credentials
        mock_request.headers = Headers({"authorization": f"Basic {encoded}"})
        
        # Mock the repository to raise an exception
        basic_auth_middleware._credentials_repository.get_by_id = AsyncMock(
            side_effect=Exception("Database error")
        )
        
        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(Exception):
                await basic_auth_middleware.get_current_user(mock_request)
