from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from auth_middleware.jwt_bearer_manager import JWTBearerManager


@pytest.mark.asyncio
@patch("auth_middleware.jwt_bearer_manager.settings")
async def test_get_credentials_disabled_middleware(mock_settings):
    mock_settings.AUTH_MIDDLEWARE_DISABLED = True
    manager = JWTBearerManager(auth_provider=MagicMock())

    request = MagicMock(spec=Request)
    credentials = await manager.get_credentials(request)

    assert credentials is None


@pytest.mark.asyncio
@patch("auth_middleware.jwt_bearer_manager.settings")
async def test_get_credentials_valid_token(mock_settings):
    mock_settings.AUTH_MIDDLEWARE_DISABLED = False
    mock_auth_provider = MagicMock()
    mock_auth_provider.verify_token.return_value = True
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    request = MagicMock(spec=Request)
    request.headers = {"Authorization": "Bearer valid_token"}
    credentials = await manager.get_credentials(request)

    assert credentials is not None
    assert credentials.jwt_token == "valid_token"
    assert credentials.header == {"alg": "HS256", "typ": "JWT"}
    assert credentials.claims == {"sub": "1234567890", "name": "John Doe"}
    assert credentials.signature == "signature"
    assert credentials.message == "message"


@pytest.mark.asyncio
@patch("auth_middleware.jwt_bearer_manager.settings")
async def test_get_credentials_invalid_token(mock_settings):
    mock_settings.AUTH_MIDDLEWARE_DISABLED = False
    mock_auth_provider = MagicMock()
    mock_auth_provider.verify_token.return_value = False
    manager = JWTBearerManager(auth_provider=mock_auth_provider)

    request = MagicMock(spec=Request)
    request.headers = {"Authorization": "Bearer invalid_token"}

    try:
        await manager.get_credentials(request)
        assert False, "Expected InvalidTokenException to be raised"
    except HTTPException as e:
        assert e.status_code == 403
        assert e.detail == "JWK_invalid"
