import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from jose import jwt
from starlette.requests import Request
from starlette.types import Scope

from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.jwt_bearer_manager import JWTBearerManager


@pytest.mark.asyncio
async def test_get_credentials_disabled_middleware():
    manager = JWTBearerManager(auth_provider=MagicMock())

    scope = {"type": "http"}
    request: Request = Request(scope=scope)

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", True):
        credentials = await manager.get_credentials(request)

        assert credentials is None


@pytest.mark.asyncio
async def test_get_credentials_valid_token():
    mock_auth_provider = AsyncMock()
    mock_auth_provider.verify_token.return_value = True
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    # Define your secret key. This should be a secure, unguessable string.
    secret = "my_secret_key"

    # Define the payload. This is the data that will be included in the token.
    # In a real application, this might include info about the user.

    # TODO: send to utilities file
    payload = {
        "sub": "2fMX3FwVHqJXleMwtDdV4xGjrum",
        "token_use": "access",
        "scope": "server-rsid/administrator",
        "auth_time": int(time.time()),
        "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_something",
        "exp": int(time.time()) + 3600,  # The token will expire one hour from now.
        "iat": int(time.time()),
        "version": 2,
        "jti": str(uuid.uuid4()),  # Generate a new UUID for each token.
        "client_id": "2fMX3FwVHqJXleMwtDdV4xGjrum",
    }

    # Generate the token.
    token = jwt.encode(payload, secret, algorithm="HS256")
    message, signature = token.rsplit(".", 1)

    authorization = b"Bearer " + token.encode()

    scope: Scope = {
        "type": "http",
        "headers": [(b"authorization", authorization)],
    }
    request: Request = Request(scope=scope)

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        credentials = await manager.get_credentials(request)

    assert credentials is not None
    assert credentials.jwt_token == token
    assert credentials.header == {"alg": "HS256", "typ": "JWT"}
    assert credentials.claims["sub"] == "2fMX3FwVHqJXleMwtDdV4xGjrum"
    assert credentials.signature == signature
    assert credentials.message == message


@pytest.mark.asyncio
async def test_get_credentials_invalid_token():
    mock_auth_provider = AsyncMock()
    mock_auth_provider.verify_token.return_value = False
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    # Define your secret key. This should be a secure, unguessable string.
    secret = "my_secret_key"

    # Define the payload. This is the data that will be included in the token.
    # In a real application, this might include info about the user.

    # TODO: send to utilities file
    payload = {
        "sub": "2fMX3FwVHqJXleMwtDdV4xGjrum",
        "token_use": "access",
        "scope": "server-rsid/administrator",
        "auth_time": int(time.time()),
        "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_something",
        "exp": int(time.time()) + 3600,  # The token will expire one hour from now.
        "iat": int(time.time()),
        "version": 2,
        "jti": str(uuid.uuid4()),  # Generate a new UUID for each token.
        "client_id": "2fMX3FwVHqJXleMwtDdV4xGjrum",
    }

    # Generate the token.
    token = jwt.encode(payload, secret, algorithm="HS256")
    message, signature = token.rsplit(".", 1)

    authorization = b"Bearer " + token.encode()

    scope: Scope = {
        "type": "http",
        "headers": [(b"authorization", authorization)],
    }
    request: Request = Request(scope=scope)

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        with pytest.raises(InvalidTokenException) as exc_info:
            await manager.get_credentials(request)

        # Assert that the exception has the correct status code and detail
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "JWK_invalid"


@pytest.mark.asyncio
async def test_get_credentials_no_authorization_header():
    """Test get_credentials when no authorization header is present."""
    mock_auth_provider = AsyncMock()
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    scope: Scope = {
        "type": "http",
        "headers": [],  # No authorization header
    }
    request: Request = Request(scope=scope)

    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        # Should raise HTTPException when no credentials
        with pytest.raises(HTTPException) as exc_info:
            await manager.get_credentials(request)
        assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_get_credentials_wrong_scheme():
    """Test get_credentials with wrong authentication scheme."""
    mock_auth_provider = AsyncMock()
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    authorization = b"Basic dXNlcm5hbWU6cGFzc3dvcmQ="  # Basic auth instead of Bearer

    scope: Scope = {
        "type": "http",
        "headers": [(b"authorization", authorization)],
    }
    request: Request = Request(scope=scope)

    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        # HTTPBearer will raise HTTPException for wrong scheme
        with pytest.raises(HTTPException) as exc_info:
            await manager.get_credentials(request)
        
        assert exc_info.value.status_code == 403


@pytest.mark.asyncio 
async def test_get_credentials_malformed_jwt():
    """Test get_credentials with malformed JWT token."""
    mock_auth_provider = AsyncMock()
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    # Malformed JWT token (missing dots)
    malformed_token = "invalidtoken"
    authorization = b"Bearer " + malformed_token.encode()

    scope: Scope = {
        "type": "http",
        "headers": [(b"authorization", authorization)],
    }
    request: Request = Request(scope=scope)

    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        with pytest.raises(ValueError):  # rsplit will fail on malformed token
            await manager.get_credentials(request)


@pytest.mark.asyncio
async def test_get_credentials_jwt_decode_error():
    """Test get_credentials when JWT decoding fails."""
    mock_auth_provider = AsyncMock()
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    # Use an invalid JWT token that will cause decode error
    invalid_token = "invalid.jwt.token"
    authorization = b"Bearer " + invalid_token.encode()

    scope: Scope = {
        "type": "http",
        "headers": [(b"authorization", authorization)],
    }
    request: Request = Request(scope=scope)

    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        with pytest.raises(InvalidTokenException) as exc_info:
            await manager.get_credentials(request)
        
        assert exc_info.value.status_code == 403
        assert "JWK-invalid" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_get_credentials_auth_provider_verify_exception():
    """Test get_credentials when auth provider verify_token raises exception."""
    mock_auth_provider = AsyncMock()
    mock_auth_provider.verify_token.side_effect = Exception("Provider error")
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    secret = "my_secret_key"
    payload = {
        "sub": "test_user",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }

    token = jwt.encode(payload, secret, algorithm="HS256")
    authorization = b"Bearer " + token.encode()

    scope: Scope = {
        "type": "http",
        "headers": [(b"authorization", authorization)],
    }
    request: Request = Request(scope=scope)

    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        with pytest.raises(Exception, match="Provider error"):
            await manager.get_credentials(request)


@pytest.mark.asyncio
async def test_get_credentials_empty_bearer_token():
    """Test get_credentials with empty Bearer token."""
    mock_auth_provider = AsyncMock()
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    authorization = b"Bearer "  # Empty token

    scope: Scope = {
        "type": "http",
        "headers": [(b"authorization", authorization)],
    }
    request: Request = Request(scope=scope)

    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        # HTTPBearer should raise HTTPException for empty token
        with pytest.raises(HTTPException) as exc_info:
            await manager.get_credentials(request)
        assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_manager_initialization():
    """Test JWTBearerManager initialization."""
    mock_auth_provider = AsyncMock()
    
    # Test with default auto_error
    manager1 = JWTBearerManager(auth_provider=mock_auth_provider)
    assert manager1.auth_provider is mock_auth_provider
    assert manager1.auto_error is True
    
    # Test with auto_error=False
    manager2 = JWTBearerManager(auth_provider=mock_auth_provider, auto_error=False)
    assert manager2.auth_provider is mock_auth_provider
    assert manager2.auto_error is False


@pytest.mark.asyncio
async def test_get_credentials_with_complex_jwt():
    """Test get_credentials with JWT containing complex claims."""
    mock_auth_provider = AsyncMock()
    mock_auth_provider.verify_token.return_value = True
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    secret = "my_secret_key"
    payload = {
        "sub": "user123",
        "username": "testuser",
        "email": "test@example.com",
        "roles": ["admin", "user"],
        "permissions": ["read", "write", "delete"],
        "metadata": {
            "last_login": "2023-01-01T00:00:00Z",
            "login_count": 42
        },
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "iss": "https://example.com",
        "aud": "my-app"
    }

    token = jwt.encode(payload, secret, algorithm="HS256")
    authorization = b"Bearer " + token.encode()

    scope: Scope = {
        "type": "http",
        "headers": [(b"authorization", authorization)],
    }
    request: Request = Request(scope=scope)

    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        credentials = await manager.get_credentials(request)

    assert credentials is not None
    assert credentials.claims["username"] == "testuser"
    assert credentials.claims["email"] == "test@example.com"
    assert credentials.claims["roles"] == ["admin", "user"]
    assert credentials.claims["metadata"]["login_count"] == 42


@pytest.mark.asyncio
async def test_get_credentials_case_sensitive_bearer():
    """Test that Bearer scheme is case sensitive."""
    mock_auth_provider = AsyncMock()
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    token = "header.payload.signature"
    
    # Test different cases - all should fail except exact "Bearer"
    test_cases = ["bearer", "BEARER", "bEaReR"]
    
    for scheme in test_cases:
        authorization = f"{scheme} {token}".encode()
        
        scope: Scope = {
            "type": "http",
            "headers": [(b"authorization", authorization)],
        }
        request: Request = Request(scope=scope)

        with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(InvalidTokenException) as exc_info:
                await manager.get_credentials(request)
            
            assert "Wrong authentication method" in str(exc_info.value.detail)
