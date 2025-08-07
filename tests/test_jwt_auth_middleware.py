"""
Comprehensive tests for auth_middleware.jwt_auth_middleware module.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, State
from starlette.responses import Response
from starlette.types import ASGIApp

from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
from auth_middleware.types.user import User


class TestJwtAuthMiddleware:
    """Test cases for JwtAuthMiddleware class."""

    def test_init_with_auth_provider(self, mock_auth_provider):
        """Test JwtAuthMiddleware initialization with auth provider."""
        app = Mock(spec=ASGIApp)

        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        assert middleware._auth_provider == mock_auth_provider
        assert middleware._jwt_bearer_manager is not None

    def test_init_creates_jwt_bearer_manager(self, mock_auth_provider):
        """Test that JwtAuthMiddleware creates JWT bearer manager."""
        app = Mock(spec=ASGIApp)

        with patch(
            "auth_middleware.jwt_auth_middleware.JWTBearerManager"
        ) as mock_bearer_manager_class:
            mock_bearer_manager = Mock()
            mock_bearer_manager_class.return_value = mock_bearer_manager

            middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

            mock_bearer_manager_class.assert_called_once_with(
                auth_provider=mock_auth_provider
            )
            assert middleware._jwt_bearer_manager == mock_bearer_manager

    @pytest.mark.asyncio
    async def test_dispatch_success(self, mock_auth_provider, sample_user):
        """Test successful dispatch with valid authentication."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        # Mock request and response
        request = Mock(spec=Request)
        request.state = State()

        response = Response("Success", status_code=200)
        call_next = AsyncMock(return_value=response)

        # Mock get_current_user to return a user
        middleware.get_current_user = AsyncMock(return_value=sample_user)

        # Execute
        result = await middleware.dispatch(request, call_next)

        # Verify
        assert request.state.current_user == sample_user
        call_next.assert_called_once_with(request)
        assert result == response

    @pytest.mark.asyncio
    async def test_dispatch_with_invalid_token_exception(self, mock_auth_provider):
        """Test dispatch handling InvalidTokenException."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        request = Mock(spec=Request)
        request.state = State()
        call_next = AsyncMock()

        # Mock get_current_user to raise InvalidTokenException
        middleware.get_current_user = AsyncMock(
            side_effect=InvalidTokenException(status_code=401, detail="Invalid token")
        )

        # Execute
        result = await middleware.dispatch(request, call_next)

        # Verify
        assert isinstance(result, JSONResponse)
        assert result.status_code == status.HTTP_401_UNAUTHORIZED
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_with_general_exception(self, mock_auth_provider):
        """Test dispatch handling general exceptions."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        request = Mock(spec=Request)
        request.state = State()
        call_next = AsyncMock()

        # Mock get_current_user to raise general exception
        middleware.get_current_user = AsyncMock(side_effect=Exception("Database error"))

        # Execute
        result = await middleware.dispatch(request, call_next)

        # Verify
        assert isinstance(result, JSONResponse)
        assert result.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_current_user_with_valid_credentials(
        self, mock_auth_provider, sample_jwt_token, sample_user
    ):
        """Test get_current_user with valid credentials."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        # Setup request with authorization header
        request = Mock(spec=Request)
        request.headers = Headers({"authorization": "Bearer valid-token"})

        # Mock JWT bearer manager and auth provider
        middleware._jwt_bearer_manager.get_credentials = AsyncMock(
            return_value=sample_jwt_token
        )
        mock_auth_provider.create_user_from_token = AsyncMock(return_value=sample_user)

        # Execute
        result = await middleware.get_current_user(request)

        # Verify
        assert result == sample_user
        middleware._jwt_bearer_manager.get_credentials.assert_called_once_with(
            request=request
        )
        mock_auth_provider.create_user_from_token.assert_called_once_with(
            token=sample_jwt_token
        )

    @pytest.mark.asyncio
    async def test_get_current_user_without_credentials(self, mock_auth_provider):
        """Test get_current_user without credentials."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        # Setup request without authorization header
        request = Mock(spec=Request)
        request.headers = Headers({})

        # Execute
        result = await middleware.get_current_user(request)

        # Verify
        assert result is None

    @pytest.mark.asyncio
    async def test_get_current_user_with_invalid_token(self, mock_auth_provider):
        """Test get_current_user with invalid token raising exception."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        # Setup request with authorization header
        request = Mock(spec=Request)
        request.headers = Headers({"authorization": "Bearer invalid-token"})

        # Mock JWT bearer manager to raise InvalidTokenException
        middleware._jwt_bearer_manager.get_credentials = AsyncMock(
            side_effect=InvalidTokenException(status_code=401, detail="Invalid token")
        )

        # Execute and verify exception is propagated
        with pytest.raises(InvalidTokenException):
            await middleware.get_current_user(request)

    @pytest.mark.asyncio
    async def test_get_current_user_with_no_token_returns_synthetic(
        self, mock_auth_provider
    ):
        """Test get_current_user returns synthetic user when no token."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        # Setup request with authorization header but no token returned
        request = Mock(spec=Request)
        request.headers = Headers({"authorization": "Bearer some-token"})

        # Mock JWT bearer manager to return None
        middleware._jwt_bearer_manager.get_credentials = AsyncMock(return_value=None)

        # Execute
        result = await middleware.get_current_user(request)

        # Verify synthetic user is returned
        assert result is not None
        assert result.id == "synthetic"
        assert result.name == "synthetic"
        assert result.email == "synthetic@email.com"
        assert await result.groups == []

    @pytest.mark.asyncio
    async def test_get_current_user_with_general_exception(self, mock_auth_provider):
        """Test get_current_user handling general exceptions."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        # Setup request with authorization header
        request = Mock(spec=Request)
        request.headers = Headers({"authorization": "Bearer some-token"})

        # Mock JWT bearer manager to raise general exception
        middleware._jwt_bearer_manager.get_credentials = AsyncMock(
            side_effect=Exception("Connection error")
        )

        # Execute and verify exception is propagated
        with pytest.raises(Exception) as exc_info:
            await middleware.get_current_user(request)

        assert "Connection error" in str(exc_info.value)

    def test_validate_credentials_with_valid_auth_header(self, mock_auth_provider):
        """Test __validate_credentials with valid authorization header."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        request = Mock(spec=Request)
        request.headers = Headers({"authorization": "Bearer valid-token"})

        result = middleware._JwtAuthMiddleware__validate_credentials(request)

        assert result is True

    def test_validate_credentials_with_no_auth_header(self, mock_auth_provider):
        """Test __validate_credentials with no authorization header."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        request = Mock(spec=Request)
        request.headers = Headers({})

        result = middleware._JwtAuthMiddleware__validate_credentials(request)

        assert result is False

    def test_validate_credentials_with_invalid_scheme(self, mock_auth_provider):
        """Test __validate_credentials with invalid authorization scheme."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        request = Mock(spec=Request)
        request.headers = Headers({"authorization": "Basic invalid-token"})

        result = middleware._JwtAuthMiddleware__validate_credentials(request)

        assert result is True  # Basic scheme still has scheme and credentials

    def test_validate_credentials_with_empty_credentials(self, mock_auth_provider):
        """Test __validate_credentials with empty credentials."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        request = Mock(spec=Request)
        request.headers = Headers({"authorization": "Bearer "})

        result = middleware._JwtAuthMiddleware__validate_credentials(request)

        assert result is False

    @pytest.mark.asyncio
    async def test_create_synthetic_user(self, mock_auth_provider):
        """Test __create_synthetic_user method."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        synthetic_user = middleware._JwtAuthMiddleware__create_synthetic_user()

        assert isinstance(synthetic_user, User)
        assert synthetic_user.id == "synthetic"
        assert synthetic_user.name == "synthetic"
        assert synthetic_user.email == "synthetic@email.com"
        assert await synthetic_user.groups == []

    @pytest.mark.asyncio
    @patch("auth_middleware.jwt_auth_middleware.logger")
    async def test_logging_in_get_current_user(self, mock_logger, mock_auth_provider):
        """Test that get_current_user logs appropriate messages."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        request = Mock(spec=Request)
        request.headers = Headers({})

        # Execute
        await middleware.get_current_user(request)

        # Verify debug log was called
        mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    @patch("auth_middleware.jwt_auth_middleware.logger")
    async def test_error_logging_in_dispatch(self, mock_logger, mock_auth_provider):
        """Test error logging in dispatch method."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        request = Mock(spec=Request)
        request.state = State()
        call_next = AsyncMock()

        # Mock get_current_user to raise InvalidTokenException
        middleware.get_current_user = AsyncMock(
            side_effect=InvalidTokenException(status_code=401, detail="Invalid token")
        )

        # Execute
        await middleware.dispatch(request, call_next)

        # Verify error log was called
        mock_logger.error.assert_called()


class TestJwtAuthMiddlewareIntegration:
    """Integration tests for JwtAuthMiddleware."""

    @pytest.mark.asyncio
    async def test_full_authentication_flow(
        self, mock_auth_provider, sample_jwt_token, sample_user
    ):
        """Test complete authentication flow from request to response."""
        app = Mock(spec=ASGIApp)

        # Setup middleware
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        # Setup request
        request = Mock(spec=Request)
        request.headers = Headers({"authorization": "Bearer valid-token"})
        request.state = State()

        # Setup mocks
        middleware._jwt_bearer_manager.get_credentials = AsyncMock(
            return_value=sample_jwt_token
        )
        mock_auth_provider.create_user_from_token = AsyncMock(return_value=sample_user)

        # Setup call_next
        expected_response = Response("Protected content", status_code=200)
        call_next = AsyncMock(return_value=expected_response)

        # Execute
        result = await middleware.dispatch(request, call_next)

        # Verify full flow
        assert request.state.current_user == sample_user
        call_next.assert_called_once_with(request)
        assert result == expected_response
        middleware._jwt_bearer_manager.get_credentials.assert_called_once()
        mock_auth_provider.create_user_from_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_middleware_with_multiple_requests(
        self, mock_auth_provider, sample_user
    ):
        """Test middleware handling multiple requests."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        # Setup multiple requests
        requests = []
        for i in range(3):
            request = Mock(spec=Request)
            request.headers = Headers({"authorization": f"Bearer token-{i}"})
            request.state = State()
            requests.append(request)

        # Mock get_current_user
        middleware.get_current_user = AsyncMock(return_value=sample_user)

        call_next = AsyncMock(return_value=Response("OK"))

        # Execute multiple requests
        for request in requests:
            await middleware.dispatch(request, call_next)
            assert request.state.current_user == sample_user

        # Verify all requests were processed
        assert middleware.get_current_user.call_count == 3
        assert call_next.call_count == 3

    @pytest.mark.asyncio
    async def test_middleware_error_recovery(self, mock_auth_provider):
        """Test middleware recovery from errors."""
        app = Mock(spec=ASGIApp)
        middleware = JwtAuthMiddleware(app, auth_provider=mock_auth_provider)

        request = Mock(spec=Request)
        request.state = State()
        call_next = AsyncMock()

        # First request fails
        middleware.get_current_user = AsyncMock(
            side_effect=Exception("Temporary error")
        )
        result1 = await middleware.dispatch(request, call_next)

        assert isinstance(result1, JSONResponse)
        assert result1.status_code == 500

        # Second request succeeds
        sample_user = User(id="test", name="Test User", email="test@example.com")
        middleware.get_current_user = AsyncMock(return_value=sample_user)

        request2 = Mock(spec=Request)
        request2.state = State()
        expected_response = Response("Success")
        call_next.return_value = expected_response

        result2 = await middleware.dispatch(request2, call_next)

        assert result2 == expected_response
        assert request2.state.current_user == sample_user
