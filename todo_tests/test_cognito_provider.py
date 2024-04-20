import pytest

from auth_middleware.providers.cognito.cognito_provider import CognitoProvider
from auth_middleware.providers.cognito.exceptions import AWSException
from auth_middleware.types import JWKS, JWTAuthorizationCredentials, User


@pytest.fixture
def cognito_provider():
    return CognitoProvider()


def test_load_jwks(cognito_provider):
    jwks = cognito_provider.load_jwks()
    assert isinstance(jwks, JWKS)
    assert isinstance(jwks.keys, list)
    assert isinstance(jwks.timestamp, int)
    assert isinstance(jwks.usage_counter, int)


def test_verify_token_valid(cognito_provider):
    token = JWTAuthorizationCredentials(
        signature="valid_signature", message="valid_message", claims={"exp": 1234567890}
    )
    result = cognito_provider.verify_token(token)
    assert result == True


def test_verify_token_invalid(cognito_provider):
    token = JWTAuthorizationCredentials(
        signature="invalid_signature",
        message="invalid_message",
        claims={"exp": 1234567890},
    )
    result = cognito_provider.verify_token(token)
    assert result == False


def test_verify_token_expired(cognito_provider):
    token = JWTAuthorizationCredentials(
        signature="valid_signature", message="valid_message", claims={"exp": 1234567890}
    )
    result = cognito_provider.verify_token(token)
    assert result == False


def test_create_user_from_token(cognito_provider):
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
    assert user.email == None


def test_create_user_from_token_no_groups(cognito_provider):
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
    assert user.email == None
