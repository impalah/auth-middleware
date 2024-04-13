from unittest.mock import MagicMock, patch

import pytest

from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider


@pytest.fixture
def mock_openid_config():
    return {
        "jwks_uri": "https://example.com/jwks",
    }


@pytest.fixture
def mock_jwks():
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "key1",
                "use": "sig",
                "n": "public_key",
                "e": "exponent",
            }
        ]
    }


@pytest.fixture
def mock_token():
    return MagicMock()


@pytest.fixture
def mock_settings():
    return {
        "AUTH_PROVIDER_AZURE_ENTRA_ID_JWKS_URL_TEMPLATE": "https://example.com/jwks/{}",
        "AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID": "tenant_id",
        "AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES": 60,
        "AUTH_MIDDLEWARE_JWKS_CACHE_USAGES": 100,
        "AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID": "audience_id",
    }


@patch("requests.get")
def test_load_jwks(mock_requests_get, mock_openid_config, mock_jwks, mock_settings):
    mock_requests_get.side_effect = [
        MagicMock(json=lambda: mock_openid_config),
        MagicMock(json=lambda: mock_jwks),
    ]

    provider = EntraIDProvider()
    provider.settings = mock_settings

    jwks = provider.load_jwks()

    mock_requests_get.assert_called_with("https://example.com/jwks/tenant_id")
    assert len(jwks.keys) == 1
    assert jwks.keys[0]["kid"] == "key1"


def test_verify_token_with_valid_token(mock_token):
    provider = EntraIDProvider()
    provider._get_hmac_key = MagicMock(return_value={"kty": "RSA"})
    provider.settings = {
        "AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID": "audience_id",
    }

    result = provider.verify_token(mock_token)

    assert result is True


def test_verify_token_with_invalid_token(mock_token):
    provider = EntraIDProvider()
    provider._get_hmac_key = MagicMock(return_value=None)

    result = provider.verify_token(mock_token)

    assert result is False


def test_create_user_from_token(mock_token):
    mock_token.claims = {
        "sub": "user_id",
        "username": "username",
        "preferred_username": "preferred_username",
        "groups": ["group1", "group2"],
        "email": "user@example.com",
    }

    provider = EntraIDProvider()

    user = provider.create_user_from_token(mock_token)

    assert user.id == "user_id"
    assert user.name == "username"
    assert user.groups == ["group1", "group2"]
    assert user.email == "user@example.com"
