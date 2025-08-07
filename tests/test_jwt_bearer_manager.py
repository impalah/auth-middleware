import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
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
