import asyncio
import hashlib
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import httpx
import pytest
from jose import jwk, jwt
from jose.utils import base64url_decode

from auth_middleware.jwt import JWKS, JWTAuthorizationCredentials
from auth_middleware.providers.cognito.cognito_provider import CognitoProvider
from auth_middleware.providers.cognito.exceptions import AWSException
from auth_middleware.user import User


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


@patch(
    "auth_middleware.providers.cognito.cognito_provider.httpx.AsyncClient.get",
    return_value=httpx.Response(
        200,
        json={
            "keys": [
                {
                    "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
                    "alg": "RS256",
                    "kty": "RSA",
                },
                {
                    "kid": "key2",
                    "alg": "RS256",
                    "kty": "RSA",
                },
            ]
        },
    ),
)
@pytest.mark.asyncio
async def test_verify_token_valid(mocker, cognito_provider):

    # Mock the jwk.construct method
    mock_jwk_construct = Mock()

    with patch("jose.jwk.construct", mock_jwk_construct):

        # Mock the _get_hmac_key method
        mock_hmac_key = AsyncMock()
        cognito_provider._get_hmac_key = mock_hmac_key
        mock_hmac_key.return_value = {
            "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
            "alg": "RS256",
            "kty": "RSA",
        }

        # Mock the base64url_decode method
        mock_base64url_decode = Mock(return_value="valid_signature")
        base64url_decode = mock_base64url_decode

        # TODO: send to utilities file
        token = JWTAuthorizationCredentials(
            jwt_token="my_token",
            header={
                "alg": "RS256",
                "typ": "JWT",
                "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
            },
            signature="valid_signature",
            message="valid_message",
            claims={
                "sub": "1234567890",
                "username": "test_user",
                "cognito:groups": ["group1", "group2"],
                "email": "test@example.com",
                "exp": time.time() + 3600,
            },
        )

        # Mock the verify method of the hmac_key
        mock_hmac_key.verify.return_value = True

        result = await cognito_provider.verify_token(token)

    assert result is True


@patch(
    "auth_middleware.providers.cognito.cognito_provider.httpx.AsyncClient.get",
    return_value=httpx.Response(
        200,
        json={
            "keys": [
                {
                    "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
                    "alg": "RS256",
                    "kty": "RSA",
                },
                {
                    "kid": "key2",
                    "alg": "RS256",
                    "kty": "RSA",
                },
            ]
        },
    ),
)
@pytest.mark.asyncio
async def test_verify_token_invalid(mocker, cognito_provider):

    # Mock the jwk.construct method
    mock_jwk_construct = Mock()

    with patch("jose.jwk.construct", mock_jwk_construct):

        # Mock the _get_hmac_key method
        mock_hmac_key = AsyncMock()
        cognito_provider._get_hmac_key = mock_hmac_key
        mock_hmac_key.return_value = {
            "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
            "alg": "RS256",
            "kty": "RSA",
        }

        # Mock the base64url_decode method
        mock_base64url_decode = Mock()
        base64url_decode = mock_base64url_decode

        # TODO: send to utilities file
        token = JWTAuthorizationCredentials(
            jwt_token="my_token",
            header={
                "alg": "RS256",
                "typ": "JWT",
                "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
            },
            signature="valid_signature",
            message="valid_message",
            claims={
                "sub": "1234567890",
                "username": "test_user",
                "cognito:groups": ["group1", "group2"],
                "email": "test@example.com",
                "exp": time.time() - 3600,
            },
        )

        # Mock the verify method of the hmac_key
        mock_hmac_key.verify.return_value = True

        result = await cognito_provider.verify_token(token)

    assert result is False


@patch(
    "auth_middleware.providers.cognito.cognito_provider.httpx.AsyncClient.get",
    return_value=httpx.Response(
        200,
        json={
            "keys": [
                {
                    "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
                    "alg": "RS256",
                    "kty": "RSA",
                },
                {
                    "kid": "key2",
                    "alg": "RS256",
                    "kty": "RSA",
                },
            ]
        },
    ),
)
@pytest.mark.asyncio
async def test_verify_token_no_hmac_key_candidate(mocker, cognito_provider):

    # Mock the jwk.construct method
    mock_jwk_construct = Mock()

    with patch("jose.jwk.construct", mock_jwk_construct):

        # Mock the _get_hmac_key method
        mock_hmac_key = AsyncMock()
        cognito_provider._get_hmac_key = mock_hmac_key
        mock_hmac_key.return_value = None

        # Mock the base64url_decode method
        mock_base64url_decode = Mock(return_value="valid_signature")
        base64url_decode = mock_base64url_decode

        # TODO: send to utilities file
        token = JWTAuthorizationCredentials(
            jwt_token="my_token",
            header={
                "alg": "RS256",
                "typ": "JWT",
                "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
            },
            signature="valid_signature",
            message="valid_message",
            claims={
                "sub": "1234567890",
                "username": "test_user",
                "cognito:groups": ["group1", "group2"],
                "email": "test@example.com",
                "exp": time.time() + 3600,
            },
        )

        # Mock the verify method of the hmac_key
        mock_hmac_key.verify.return_value = True

        with pytest.raises(AWSException) as exc_info:
            result = await cognito_provider.verify_token(token)

        # Assert that the exception has the correct status code and detail
        assert str(exc_info.value) == "No public key found!"


def test_create_user_from_token(cognito_provider):
    # Create a token with all properties
    token = JWTAuthorizationCredentials(
        jwt_token="my_token",
        header={"alg": "HS256", "typ": "JWT"},
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


def test_create_user_from_token_using_scope(cognito_provider):
    # Create a token with all properties
    token = JWTAuthorizationCredentials(
        jwt_token="my_token",
        header={"alg": "HS256", "typ": "JWT"},
        signature="valid_signature",
        message="valid_message",
        claims={
            "sub": "1234567890",
            "username": "test_user",
            "scope": "rsid/group1",
            "email": "test@example.com",
        },
    )

    user = cognito_provider.create_user_from_token(token)

    assert isinstance(user, User)
    assert user.id == "1234567890"
    assert user.name == "test_user"
    assert user.groups == ["group1"]
    assert user.email == "test@example.com"


def test_create_user_from_token_missing_properties(cognito_provider):
    # Create a token with missing properties
    token = JWTAuthorizationCredentials(
        jwt_token="my_token",
        header={"alg": "HS256", "typ": "JWT"},
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
        jwt_token="my_token",
        header={"alg": "HS256", "typ": "JWT"},
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
    assert user.groups == []
    assert user.email is None
