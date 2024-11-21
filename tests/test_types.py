from auth_middleware.jwt import JWKS, JWTAuthorizationCredentials
from auth_middleware.user import User


def test_jwks_model():
    keys = [
        {"key1": "value1"},
        {"key2": "value2"},
    ]
    jwks = JWKS(keys=keys, timestamp=123456789, usage_counter=10)

    assert jwks.keys == keys
    assert jwks.timestamp == 123456789
    assert jwks.usage_counter == 10


def test_jwt_authorization_credentials_model():
    jwt_token = "example_token"
    header = {"alg": "HS256"}
    claims = {"sub": "user123", "exp": 1234567890}
    signature = "example_signature"
    message = "example_message"

    credentials = JWTAuthorizationCredentials(
        jwt_token=jwt_token,
        header=header,
        claims=claims,
        signature=signature,
        message=message,
    )

    assert credentials.jwt_token == jwt_token
    assert credentials.header == header
    assert credentials.claims == claims
    assert credentials.signature == signature
    assert credentials.message == message


def test_user_model():
    user_id = "0ujsswThIGTUYm2K8FjOOfXtY1K"
    name = "test_user"
    email = "useradmin@user.com"
    groups = ["admin", "user"]

    user = User(id=user_id, name=name, email=email, groups=groups)

    assert user.id == user_id
    assert user.name == name
    assert user.email == email
    assert user.groups == groups
