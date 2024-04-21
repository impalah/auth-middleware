import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import httpx
import pytest
from jose import jwk
from jose.utils import base64url_decode

from auth_middleware.providers.cognito.cognito_provider import CognitoProvider
from auth_middleware.providers.cognito.exceptions import AWSException
from auth_middleware.types import JWKS, JWTAuthorizationCredentials, User


@pytest.fixture
def cognito_provider():
    return CognitoProvider()


@patch(
    "auth_middleware.providers.cognito.cognito_provider.httpx.AsyncClient.get",
    return_value=httpx.Response(200, json={"keys": [{"kid": "key1"}, {"kid": "key2"}]}),
)
@pytest.mark.asyncio
async def test_get_keys(mocker, cognito_provider):

    keys = await cognito_provider.get_keys()

    assert isinstance(keys, list)
    assert len(keys) == 2
    assert keys[0]["kid"] == "key1"
    assert keys[1]["kid"] == "key2"


@patch(
    "auth_middleware.providers.cognito.cognito_provider.httpx.AsyncClient.get",
    return_value=httpx.Response(200, json={"keys": [{"kid": "key1"}, {"kid": "key2"}]}),
)
@pytest.mark.asyncio
async def test_load_jwks(mocker, cognito_provider):
    # Mock the get_keys method
    mock_keys = [{"kid": "key1"}, {"kid": "key2"}]

    jwks = await cognito_provider.load_jwks()

    assert isinstance(jwks, JWKS)
    assert jwks.keys == mock_keys


@pytest.mark.asyncio
async def test_verify_token_valid(cognito_provider):
    # Mock the _get_hmac_key method
    mock_hmac_key = Mock()
    cognito_provider._get_hmac_key = Mock(return_value=mock_hmac_key)

    # Mock the jwk.construct method
    mock_jwk_construct = Mock()
    jwk.construct = mock_jwk_construct

    # Mock the base64url_decode method
    mock_base64url_decode = Mock()
    base64url_decode = mock_base64url_decode

    # Mock the time method
    mock_time = Mock()
    cognito_provider.time = mock_time

    # Create a valid token
    token = JWTAuthorizationCredentials(
        signature="valid_signature", message="valid_message", claims={"exp": 1234567890}
    )

    # Mock the verify method of the hmac_key
    mock_hmac_key.verify.return_value = True

    result = await cognito_provider.verify_token(token)

    assert result is True
    mock_hmac_key.verify.assert_called_once_with(
        token.message.encode(), mock_base64url_decode.return_value
    )
    mock_time.assert_called_once()
    mock_jwk_construct.assert_called_once_with(mock_hmac_key)


@pytest.mark.asyncio
async def test_verify_token_invalid(cognito_provider):
    # Mock the _get_hmac_key method
    mock_hmac_key = Mock()
    cognito_provider._get_hmac_key = Mock(return_value=mock_hmac_key)

    # Mock the jwk.construct method
    mock_jwk_construct = Mock()
    jwk.construct = mock_jwk_construct

    # Mock the base64url_decode method
    mock_base64url_decode = Mock()
    base64url_decode = mock_base64url_decode

    # Mock the time method
    mock_time = Mock()
    cognito_provider.time = mock_time

    # Create an invalid token
    token = JWTAuthorizationCredentials(
        signature="invalid_signature",
        message="invalid_message",
        claims={"exp": 1234567890},
    )

    # Mock the verify method of the hmac_key
    mock_hmac_key.verify.return_value = False

    result = await cognito_provider.verify_token(token)

    assert result is False
    mock_hmac_key.verify.assert_called_once_with(
        token.message.encode(), mock_base64url_decode.return_value
    )
    mock_time.assert_not_called()
    mock_jwk_construct.assert_called_once_with(mock_hmac_key)


def test_create_user_from_token(cognito_provider):
    # Create a token with all properties
    token = JWTAuthorizationCredentials(
        signature="valid_signature",
        message="valid_message",
        claims={
            "sub": "1234567890",
            "username": "test_user",
            "cognito:groups": ["group1", "group2"],
            "email": "test@example.com",
        },
    )

    user = cognito_provider.create_user_from_token(token)

    assert isinstance(user, User)
    assert user.id == "1234567890"
    assert user.name == "test_user"
    assert user.groups == ["group1", "group2"]
    assert user.email == "test@example.com"


def test_create_user_from_token_missing_properties(cognito_provider):
    # Create a token with missing properties
    token = JWTAuthorizationCredentials(
        signature="valid_signature",
        message="valid_message",
        claims={
            "sub": "1234567890",
            "cognito:groups": ["group1", "group2"],
        },
    )

    user = cognito_provider.create_user_from_token(token)

    assert isinstance(user, User)
    assert user.id == "1234567890"
    assert user.name == "1234567890"
    assert user.groups == ["group1", "group2"]
    assert user.email is None


def test_create_user_from_token_no_groups(cognito_provider):
    # Create a token with no groups
    token = JWTAuthorizationCredentials(
        signature="valid_signature",
        message="valid_message",
        claims={
            "sub": "1234567890",
            "username": "test_user",
        },
    )

    user = cognito_provider.create_user_from_token(token)

    assert isinstance(user, User)
    assert user.id == "1234567890"
    assert user.name == "test_user"
    assert user.groups == ["scope"]
    assert user.email is None
