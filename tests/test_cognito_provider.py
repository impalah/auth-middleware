import time
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.cognito_provider import CognitoProvider
from auth_middleware.providers.authz.cognito_groups_provider import (
    CognitoGroupsProvider,
)
from auth_middleware.providers.exceptions.aws_exception import AWSException
from auth_middleware.types.jwt import JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User


@pytest.fixture
def cognito_provider():
    settings = CognitoAuthzProviderSettings(
        jwt_secret_key="test_secret_key",
        jwt_algorithm="HS256",
        jwt_token_verification_disabled=False,
        user_pool_id="us-east-1_abcdef123",
        user_pool_region="us-east-1",
        user_pool_client_id="test_client_id",
        user_pool_client_secret="test_client_secret",
        jwks_url_template="https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
    )
    return CognitoProvider(
        settings=settings,
        groups_provider=CognitoGroupsProvider,
    )


@patch(
    "auth_middleware.providers.authn.cognito_provider.httpx.AsyncClient.get",
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
    "auth_middleware.providers.authn.cognito_provider.httpx.AsyncClient.get",
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
    "auth_middleware.providers.authn.cognito_provider.httpx.AsyncClient.get",
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

        # TODO: send to utilities file
        token = JWTAuthorizationCredentials(
            jwt_token="my_token",
            header={"alg": "HS256", "typ": "JWT"},
            signature="valid_signature",
            message="valid_message",
            claims={
                "sub": "1234567890",
                "username": "test_user",
                "exp": int(time.time()) + 3600,  # Token expires in 1 hour
                "iss": "my_issuer",
                "aud": "my_audience",
                "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
            },
        )

        result = await cognito_provider.verify_token(token)

    assert result is True


@patch(
    "auth_middleware.providers.authn.cognito_provider.httpx.AsyncClient.get",
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

        # Mock the constructed JWK to have a verify method that returns False
        mock_jwk = Mock()
        mock_jwk.verify.return_value = False
        mock_jwk_construct.return_value = mock_jwk

        # TODO: send to utilities file
        token = JWTAuthorizationCredentials(
            jwt_token="my_token",
            header={"alg": "HS256", "typ": "JWT"},
            signature="valid_signature",
            message="valid_message",
            claims={
                "sub": "1234567890",
                "username": "test_user",
                "exp": int(time.time()) + 3600,  # Token expires in 1 hour
                "iss": "my_issuer",
                "aud": "my_audience",
                "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
            },
        )

        result = await cognito_provider.verify_token(token)

    assert result is False


@patch(
    "auth_middleware.providers.authn.cognito_provider.httpx.AsyncClient.get",
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

        # TODO: send to utilities file
        token = JWTAuthorizationCredentials(
            jwt_token="my_token",
            header={"alg": "HS256", "typ": "JWT"},
            signature="valid_signature",
            message="valid_message",
            claims={
                "sub": "1234567890",
                "username": "test_user",
                "exp": int(time.time()) + 3600,  # Token expires in 1 hour
                "iss": "my_issuer",
                "aud": "my_audience",
                "kid": "g23WGFYfO80xug2LFX3NGpFWFyFZByRz9iYjsHeFl4Q=",
            },
        )

        # Since there's no hmac key candidate, should raise an exception
        with pytest.raises(AWSException) as exc_info:
            await cognito_provider.verify_token(token)

        # Assert that the exception has the correct status code and detail
        assert str(exc_info.value) == "No public key found!"


@pytest.mark.asyncio
async def test_create_user_from_token(cognito_provider):
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

    user = await cognito_provider.create_user_from_token(token)

    assert isinstance(user, User)
    assert user.id == "1234567890"
    assert user.name == "test_user"
    assert await user.groups == ["group1", "group2"]
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_create_user_from_token_using_scope(cognito_provider):
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

    user = await cognito_provider.create_user_from_token(token)

    assert isinstance(user, User)
    assert user.id == "1234567890"
    assert user.name == "test_user"
    assert await user.groups == ["group1"]
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_create_user_from_token_missing_properties(cognito_provider):
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

    user = await cognito_provider.create_user_from_token(token)

    assert isinstance(user, User)
    assert user.id == "1234567890"
    assert user.name == "1234567890"
    assert await user.groups == ["group1", "group2"]
    assert user.email is None


@pytest.mark.asyncio
async def test_create_user_from_token_no_groups(cognito_provider):
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

    user = await cognito_provider.create_user_from_token(token)

    assert isinstance(user, User)
    assert user.id == "1234567890"
    assert user.name == "test_user"
    assert await user.groups == []
    assert user.email is None
