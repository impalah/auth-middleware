"""
Shared test fixtures and configuration for the auth-middleware test suite.
"""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import Request
from starlette.datastructures import Headers, State

from auth_middleware.types.jwt import JWTAuthorizationCredentials
from auth_middleware.types.user import User


@pytest.fixture
def sample_user():
    """Create a sample user for testing."""
    return User(id="test-user-123", name="Test User", email="test@example.com")


@pytest.fixture
def sample_user_with_groups():
    """Create a sample user with groups for testing."""
    user = User(id="test-user-456", name="Admin User", email="admin@example.com")
    # Mock the groups property
    user._groups = ["admin", "users"]
    return user


@pytest.fixture
def sample_user_with_permissions():
    """Create a sample user with permissions for testing."""
    user = User(id="test-user-789", name="Power User", email="power@example.com")
    # Mock the permissions property
    user._permissions = ["read", "write", "delete"]
    return user


@pytest.fixture
def mock_request_with_user(sample_user):
    """Create a mock request with authenticated user."""
    request = Mock(spec=Request)
    request.state = State()
    request.state.current_user = sample_user
    request.headers = Headers({"authorization": "Bearer valid-token"})
    return request


@pytest.fixture
def mock_request_without_user():
    """Create a mock request without authenticated user."""
    request = Mock(spec=Request)
    request.state = State()
    request.headers = Headers({})
    return request


@pytest.fixture
def mock_request_with_auth_header():
    """Create a mock request with authorization header but no user."""
    request = Mock(spec=Request)
    request.state = State()
    request.headers = Headers({"authorization": "Bearer test-token"})
    return request


@pytest.fixture
def sample_jwt_token():
    """Create a sample JWT token for testing."""
    return JWTAuthorizationCredentials(
        jwt_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature",
        header={"typ": "JWT", "alg": "HS256"},
        claims={"sub": "1234567890", "name": "John Doe", "admin": True},
        signature="signature",
        message="header.payload",
    )


@pytest.fixture
def sample_jwt_token_with_cognito_groups():
    """Create a sample JWT token with Cognito groups."""
    return JWTAuthorizationCredentials(
        jwt_token="test.token.signature",
        header={"typ": "JWT", "alg": "RS256", "kid": "test-key-id"},
        claims={
            "sub": "cognito-user-123",
            "username": "cognitouser",
            "cognito:groups": ["admin", "users"],
            "email": "cognito@example.com",
            "exp": 9999999999,  # Far future
        },
        signature="test-signature",
        message="test-message",
    )


@pytest.fixture
def mock_auth_provider():
    """Create a mock authentication provider."""
    provider = AsyncMock()
    provider.get_keys = AsyncMock(
        return_value=[
            {"kid": "key1", "alg": "RS256", "kty": "RSA"},
            {"kid": "key2", "alg": "RS256", "kty": "RSA"},
        ]
    )
    provider.load_jwks = AsyncMock()
    provider.verify_token = AsyncMock(return_value=True)
    provider.create_user_from_token = AsyncMock()
    return provider


@pytest.fixture
def mock_groups_provider():
    """Create a mock groups provider."""
    provider = AsyncMock()
    provider.fetch_groups = AsyncMock(return_value=["admin", "users"])
    return provider


@pytest.fixture
def mock_permissions_provider():
    """Create a mock permissions provider."""
    provider = AsyncMock()

    # Define a standalone async function that can be called multiple times
    async def fetch_permissions_mock(token):
        return ["read", "write", "delete"]

    provider.fetch_permissions = AsyncMock(side_effect=fetch_permissions_mock)
    return provider


@pytest.fixture(autouse=True)
def reset_settings():
    """Reset settings before each test."""
    from auth_middleware.settings import settings

    original_disabled = settings.AUTH_MIDDLEWARE_DISABLED
    settings.AUTH_MIDDLEWARE_DISABLED = False
    yield
    settings.AUTH_MIDDLEWARE_DISABLED = original_disabled


@pytest.fixture
def mock_disabled_middleware():
    """Create a fixture for disabled middleware testing."""
    from auth_middleware.settings import settings

    settings.AUTH_MIDDLEWARE_DISABLED = True
    yield
    settings.AUTH_MIDDLEWARE_DISABLED = False


# Event loop fixture for async tests
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
