"""Tests for EntraIDProvider covering previously uncovered lines."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth_middleware.providers.exceptions.azure_exception import AzureException
from auth_middleware.types.jwt import JWTAuthorizationCredentials


def _make_token(claims: dict) -> JWTAuthorizationCredentials:
    return JWTAuthorizationCredentials(
        jwt_token="header.payload.sig",
        header={"alg": "RS256", "kid": "key1"},
        claims=claims,
        signature="sig",
        message="header.payload",
    )


def _fresh_provider():
    """Return a fresh EntraIDProvider, bypassing the singleton per test."""
    from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider

    # Reset singleton so __init__ runs again
    if hasattr(EntraIDProvider, "instance"):
        del EntraIDProvider.instance

    provider = EntraIDProvider()
    return provider


# ---------------------------------------------------------------------------
# __new__ / __init__ singleton behaviour
# ---------------------------------------------------------------------------

class TestEntraIDProviderInit:
    def setup_method(self):
        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider
        if hasattr(EntraIDProvider, "instance"):
            del EntraIDProvider.instance

    def test_singleton_returns_same_instance(self):
        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider
        if hasattr(EntraIDProvider, "instance"):
            del EntraIDProvider.instance

        a = EntraIDProvider()
        b = EntraIDProvider()
        assert a is b

    def test_initialized_flag_prevents_reinit(self):
        provider = _fresh_provider()
        original_id = id(provider._groups_provider)
        # Second call with different provider should NOT reinit
        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider
        p2 = EntraIDProvider(groups_provider=MagicMock())
        assert p2 is provider
        assert id(provider._groups_provider) == original_id


# ---------------------------------------------------------------------------
# get_keys
# ---------------------------------------------------------------------------

class TestGetKeys:
    def setup_method(self):
        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider
        if hasattr(EntraIDProvider, "instance"):
            del EntraIDProvider.instance

    @pytest.mark.asyncio
    async def test_get_keys_returns_keys(self):
        provider = _fresh_provider()
        mock_response = MagicMock()
        mock_response.json.return_value = {"keys": [{"kid": "k1"}]}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await provider.get_keys("https://example.com/jwks")

        assert result == [{"kid": "k1"}]


# ---------------------------------------------------------------------------
# get_openid_config
# ---------------------------------------------------------------------------

class TestGetOpenidConfig:
    def setup_method(self):
        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider
        if hasattr(EntraIDProvider, "instance"):
            del EntraIDProvider.instance

    @pytest.mark.asyncio
    async def test_returns_config_dict(self):
        provider = _fresh_provider()
        mock_response = MagicMock()
        mock_response.json.return_value = {"jwks_uri": "https://example.com/jwks"}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await provider.get_openid_config()

        assert result["jwks_uri"] == "https://example.com/jwks"

    @pytest.mark.asyncio
    async def test_returns_empty_dict_on_exception(self):
        provider = _fresh_provider()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("network error"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await provider.get_openid_config()

        assert result == {}


# ---------------------------------------------------------------------------
# load_jwks
# ---------------------------------------------------------------------------

class TestLoadJwks:
    def setup_method(self):
        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider
        if hasattr(EntraIDProvider, "instance"):
            del EntraIDProvider.instance

    @pytest.mark.asyncio
    async def test_load_jwks_returns_jwks(self):
        provider = _fresh_provider()
        key = {"kid": "k1", "x5c": ["abc", "def"]}
        provider.get_openid_config = AsyncMock(return_value={"jwks_uri": "https://example.com/jwks"})
        provider.get_keys = AsyncMock(return_value=[key])

        jwks = await provider.load_jwks()
        # x5c list should be joined
        assert jwks.keys[0]["x5c"] == "abcdef"

    @pytest.mark.asyncio
    async def test_load_jwks_no_x5c_list(self):
        provider = _fresh_provider()
        key = {"kid": "k1"}  # no x5c
        provider.get_openid_config = AsyncMock(return_value={"jwks_uri": "https://example.com/jwks"})
        provider.get_keys = AsyncMock(return_value=[key])

        jwks = await provider.load_jwks()
        assert jwks.keys[0] == {"kid": "k1"}


# ---------------------------------------------------------------------------
# verify_token
# ---------------------------------------------------------------------------

class TestVerifyToken:
    def setup_method(self):
        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider
        if hasattr(EntraIDProvider, "instance"):
            del EntraIDProvider.instance

    @pytest.mark.asyncio
    async def test_raises_when_no_key_found(self):
        provider = _fresh_provider()
        provider._get_hmac_key = AsyncMock(return_value=None)
        token = _make_token({"sub": "u1"})

        with pytest.raises(AzureException, match="No public key found"):
            await provider.verify_token(token)

    @pytest.mark.asyncio
    async def test_returns_true_on_valid_token(self):
        from joserfc.errors import JoseError

        provider = _fresh_provider()
        hmac_key = {"kty": "RSA", "kid": "k1", "use": "sig", "n": "abc", "e": "AQAB"}
        provider._get_hmac_key = AsyncMock(return_value=hmac_key)

        mock_token_obj = MagicMock()
        mock_token_obj.claims = {"sub": "user-123"}

        with patch("auth_middleware.providers.entra_id.entra_id_provider.import_key"), \
             patch("auth_middleware.providers.entra_id.entra_id_provider.joserfc_jwt.decode", return_value=mock_token_obj), \
             patch("auth_middleware.providers.entra_id.entra_id_provider.settings") as mock_settings:
            mock_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID = None
            token = _make_token({"sub": "user-123"})
            result = await provider.verify_token(token)

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_jose_error(self):
        from joserfc.errors import JoseError

        provider = _fresh_provider()
        hmac_key = {"kty": "RSA", "kid": "k1", "use": "sig", "n": "abc", "e": "AQAB"}
        provider._get_hmac_key = AsyncMock(return_value=hmac_key)

        with patch("auth_middleware.providers.entra_id.entra_id_provider.import_key"), \
             patch("auth_middleware.providers.entra_id.entra_id_provider.joserfc_jwt.decode", side_effect=JoseError()), \
             patch("auth_middleware.providers.entra_id.entra_id_provider.settings") as mock_settings:
            mock_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID = None
            token = _make_token({"sub": "user-123"})
            result = await provider.verify_token(token)

        assert result is False

    @pytest.mark.asyncio
    async def test_raises_azure_exception_on_generic_error(self):
        provider = _fresh_provider()
        hmac_key = {"kty": "RSA", "kid": "k1", "use": "sig", "n": "abc", "e": "AQAB"}
        provider._get_hmac_key = AsyncMock(return_value=hmac_key)

        with patch("auth_middleware.providers.entra_id.entra_id_provider.import_key"), \
             patch("auth_middleware.providers.entra_id.entra_id_provider.joserfc_jwt.decode", side_effect=ValueError("bad")), \
             patch("auth_middleware.providers.entra_id.entra_id_provider.settings") as mock_settings:
            mock_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID = None
            token = _make_token({"sub": "user-123"})

            with pytest.raises(AzureException, match="Error in JWTBearerManager"):
                await provider.verify_token(token)

    @pytest.mark.asyncio
    async def test_validates_audience_when_set(self):
        provider = _fresh_provider()
        hmac_key = {"kty": "RSA", "kid": "k1", "use": "sig", "n": "abc", "e": "AQAB"}
        provider._get_hmac_key = AsyncMock(return_value=hmac_key)

        mock_token_obj = MagicMock()
        mock_token_obj.claims = {"sub": "user-123", "aud": "my-audience"}

        mock_registry = MagicMock()

        with patch("auth_middleware.providers.entra_id.entra_id_provider.import_key"), \
             patch("auth_middleware.providers.entra_id.entra_id_provider.joserfc_jwt.decode", return_value=mock_token_obj), \
             patch("auth_middleware.providers.entra_id.entra_id_provider.JWTClaimsRegistry", return_value=mock_registry), \
             patch("auth_middleware.providers.entra_id.entra_id_provider.settings") as mock_settings:
            mock_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID = "my-audience"
            token = _make_token({"sub": "user-123"})
            result = await provider.verify_token(token)

        mock_registry.validate.assert_called_once_with(mock_token_obj.claims)
        assert result is True


# ---------------------------------------------------------------------------
# create_user_from_token
# ---------------------------------------------------------------------------

class TestCreateUserFromToken:
    def setup_method(self):
        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider
        if hasattr(EntraIDProvider, "instance"):
            del EntraIDProvider.instance

    @pytest.mark.asyncio
    async def test_uses_username_claim_when_present(self):
        provider = _fresh_provider()
        token = _make_token({
            "sub": "user-1",
            "username": "johndoe",
            "email": "john@example.com",
        })
        user = await provider.create_user_from_token(token)
        assert user.id == "user-1"
        assert user.name == "johndoe"
        assert user.email == "john@example.com"

    @pytest.mark.asyncio
    async def test_falls_back_to_preferred_username(self):
        provider = _fresh_provider()
        token = _make_token({
            "sub": "user-2",
            "preferred_username": "jane",
        })
        user = await provider.create_user_from_token(token)
        assert user.name == "jane"

    @pytest.mark.asyncio
    async def test_falls_back_to_sub_when_no_name_claims(self):
        provider = _fresh_provider()
        token = _make_token({"sub": "user-3"})
        user = await provider.create_user_from_token(token)
        assert user.name == "user-3"

    @pytest.mark.asyncio
    async def test_no_email_when_missing(self):
        provider = _fresh_provider()
        token = _make_token({"sub": "user-4", "username": "u4"})
        user = await provider.create_user_from_token(token)
        assert user.email is None

    @pytest.mark.asyncio
    async def test_fetches_groups_from_provider(self):
        groups_provider = MagicMock()
        groups_provider.fetch_groups = AsyncMock(return_value=["admin", "staff"])

        from auth_middleware.providers.entra_id.entra_id_provider import EntraIDProvider
        if hasattr(EntraIDProvider, "instance"):
            del EntraIDProvider.instance

        provider = EntraIDProvider(groups_provider=groups_provider)
        token = _make_token({"sub": "user-5", "username": "u5"})
        user = await provider.create_user_from_token(token)
        assert await user.groups == ["admin", "staff"]

    @pytest.mark.asyncio
    async def test_returns_empty_groups_without_provider(self):
        provider = _fresh_provider()
        token = _make_token({"sub": "user-6", "username": "u6"})
        user = await provider.create_user_from_token(token)
        assert await user.groups == []
