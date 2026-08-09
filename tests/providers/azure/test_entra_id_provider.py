"""Tests for EntraIDProvider covering previously uncovered lines."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.providers.azure.azure_exception import AzureException
from auth_middleware.providers.azure.entra_id_provider import EntraIDProvider
from auth_middleware.types.jwt import JWTAuthorizationCredentials

_MOCK_REQUEST = httpx.Request("GET", "http://test")


def _make_token(claims: dict) -> JWTAuthorizationCredentials:
    return JWTAuthorizationCredentials(
        jwt_token="header.payload.sig",
        header={"alg": "RS256", "kid": "key1"},
        claims=claims,
        signature="sig",
        message="header.payload",
    )


def _fresh_provider(**kwargs):
    """Return a new EntraIDProvider (no shared singleton state to reset)."""
    return EntraIDProvider(**kwargs)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestEntraIDProviderInit:
    def test_creates_independent_instances(self):
        """Each instantiation is independent — there is no shared singleton
        state that could silently ignore a later call's providers (a real
        bug this used to have: a second EntraIDProvider(...) call used to
        reuse the first instance and drop the new arguments)."""
        groups_a = MagicMock()
        groups_b = MagicMock()

        a = EntraIDProvider(groups_provider=groups_a)
        b = EntraIDProvider(groups_provider=groups_b)

        assert a is not b
        assert a._groups_provider is groups_a
        assert b._groups_provider is groups_b


# ---------------------------------------------------------------------------
# get_keys
# ---------------------------------------------------------------------------


class TestGetKeys:
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

    @pytest.mark.asyncio
    async def test_raises_invalid_token_exception_on_http_error(self):
        provider = _fresh_provider()

        with patch(
            "auth_middleware.providers.azure.entra_id_provider.httpx.AsyncClient.get",
            return_value=httpx.Response(500, request=_MOCK_REQUEST),
        ):
            with pytest.raises(InvalidTokenException):
                await provider.get_keys("https://example.com/jwks")

    @pytest.mark.asyncio
    async def test_raises_invalid_token_exception_on_network_error(self):
        provider = _fresh_provider()

        with patch(
            "auth_middleware.providers.azure.entra_id_provider.httpx.AsyncClient.get",
            side_effect=httpx.ConnectError("connection refused"),
        ):
            with pytest.raises(InvalidTokenException):
                await provider.get_keys("https://example.com/jwks")

    @pytest.mark.asyncio
    async def test_raises_invalid_token_exception_on_malformed_response(self):
        provider = _fresh_provider()

        with patch(
            "auth_middleware.providers.azure.entra_id_provider.httpx.AsyncClient.get",
            return_value=httpx.Response(
                200, json={"no_keys_here": []}, request=_MOCK_REQUEST
            ),
        ):
            with pytest.raises(InvalidTokenException):
                await provider.get_keys("https://example.com/jwks")


# ---------------------------------------------------------------------------
# get_openid_config
# ---------------------------------------------------------------------------


class TestGetOpenidConfig:
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
    async def test_raises_invalid_token_exception_on_http_error(self):
        provider = _fresh_provider()

        with patch(
            "auth_middleware.providers.azure.entra_id_provider.httpx.AsyncClient.get",
            return_value=httpx.Response(500, request=_MOCK_REQUEST),
        ):
            with pytest.raises(InvalidTokenException):
                await provider.get_openid_config()

    @pytest.mark.asyncio
    async def test_raises_invalid_token_exception_on_network_error(self):
        provider = _fresh_provider()

        with patch(
            "auth_middleware.providers.azure.entra_id_provider.httpx.AsyncClient.get",
            side_effect=httpx.ConnectError("connection refused"),
        ):
            with pytest.raises(InvalidTokenException):
                await provider.get_openid_config()

    @pytest.mark.asyncio
    async def test_raises_invalid_token_exception_on_malformed_json(self):
        provider = _fresh_provider()

        with patch(
            "auth_middleware.providers.azure.entra_id_provider.httpx.AsyncClient.get",
            return_value=httpx.Response(
                200, content=b"not json", request=_MOCK_REQUEST
            ),
        ):
            with pytest.raises(InvalidTokenException):
                await provider.get_openid_config()


# ---------------------------------------------------------------------------
# load_jwks
# ---------------------------------------------------------------------------


class TestLoadJwks:
    @pytest.mark.asyncio
    async def test_load_jwks_returns_jwks(self):
        provider = _fresh_provider()
        key = {"kid": "k1", "x5c": ["abc", "def"]}
        provider.get_openid_config = AsyncMock(
            return_value={"jwks_uri": "https://example.com/jwks"}
        )
        provider.get_keys = AsyncMock(return_value=[key])

        jwks = await provider.load_jwks()
        # x5c list should be joined
        assert jwks.keys[0]["x5c"] == "abcdef"

    @pytest.mark.asyncio
    async def test_load_jwks_no_x5c_list(self):
        provider = _fresh_provider()
        key = {"kid": "k1"}  # no x5c
        provider.get_openid_config = AsyncMock(
            return_value={"jwks_uri": "https://example.com/jwks"}
        )
        provider.get_keys = AsyncMock(return_value=[key])

        jwks = await provider.load_jwks()
        assert jwks.keys[0] == {"kid": "k1"}

    @pytest.mark.asyncio
    async def test_raises_invalid_token_exception_when_jwks_uri_missing(self):
        provider = _fresh_provider()
        # Discovery document came back but doesn't have jwks_uri — must
        # raise a clear error, not a bare KeyError.
        provider.get_openid_config = AsyncMock(return_value={"issuer": "https://x"})

        with pytest.raises(InvalidTokenException):
            await provider.load_jwks()


# ---------------------------------------------------------------------------
# verify_token
# ---------------------------------------------------------------------------


class TestVerifyToken:
    @pytest.mark.asyncio
    async def test_raises_when_no_key_found(self):
        provider = _fresh_provider()
        provider._get_hmac_key = AsyncMock(return_value=None)
        token = _make_token({"sub": "u1"})

        with pytest.raises(InvalidTokenException, match="No public key found"):
            await provider.verify_token(token)

    @pytest.mark.asyncio
    async def test_returns_true_on_valid_token(self):
        provider = _fresh_provider()
        hmac_key = {"kty": "RSA", "kid": "k1", "use": "sig", "n": "abc", "e": "AQAB"}
        provider._get_hmac_key = AsyncMock(return_value=hmac_key)

        mock_token_obj = MagicMock()
        mock_token_obj.claims = {"sub": "user-123", "exp": int(time.time()) + 3600}

        with (
            patch("auth_middleware.providers.azure.entra_id_provider.import_key"),
            patch(
                "auth_middleware.providers.azure.entra_id_provider.joserfc_jwt.decode",
                return_value=mock_token_obj,
            ),
            patch(
                "auth_middleware.providers.azure.entra_id_provider.settings"
            ) as mock_settings,
        ):
            mock_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID = None
            mock_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_LEEWAY = 0
            token = _make_token({"sub": "user-123"})
            result = await provider.verify_token(token)

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_jose_error(self):
        from joserfc.errors import JoseError

        provider = _fresh_provider()
        hmac_key = {"kty": "RSA", "kid": "k1", "use": "sig", "n": "abc", "e": "AQAB"}
        provider._get_hmac_key = AsyncMock(return_value=hmac_key)

        with (
            patch("auth_middleware.providers.azure.entra_id_provider.import_key"),
            patch(
                "auth_middleware.providers.azure.entra_id_provider.joserfc_jwt.decode",
                side_effect=JoseError(),
            ),
            patch(
                "auth_middleware.providers.azure.entra_id_provider.settings"
            ) as mock_settings,
        ):
            mock_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID = None
            token = _make_token({"sub": "user-123"})
            result = await provider.verify_token(token)

        assert result is False

    @pytest.mark.asyncio
    async def test_raises_azure_exception_on_generic_error(self):
        provider = _fresh_provider()
        hmac_key = {"kty": "RSA", "kid": "k1", "use": "sig", "n": "abc", "e": "AQAB"}
        provider._get_hmac_key = AsyncMock(return_value=hmac_key)

        with (
            patch("auth_middleware.providers.azure.entra_id_provider.import_key"),
            patch(
                "auth_middleware.providers.azure.entra_id_provider.joserfc_jwt.decode",
                side_effect=ValueError("bad"),
            ),
            patch(
                "auth_middleware.providers.azure.entra_id_provider.settings"
            ) as mock_settings,
        ):
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
        mock_token_obj.claims = {
            "sub": "user-123",
            "aud": "my-audience",
            "exp": int(time.time()) + 3600,
        }

        mock_registry = MagicMock()

        with (
            patch("auth_middleware.providers.azure.entra_id_provider.import_key"),
            patch(
                "auth_middleware.providers.azure.entra_id_provider.joserfc_jwt.decode",
                return_value=mock_token_obj,
            ),
            patch(
                "auth_middleware.providers.azure.entra_id_provider.JWTClaimsRegistry",
                return_value=mock_registry,
            ),
            patch(
                "auth_middleware.providers.azure.entra_id_provider.settings"
            ) as mock_settings,
        ):
            mock_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID = "my-audience"
            mock_settings.AUTH_PROVIDER_AZURE_ENTRA_ID_LEEWAY = 0
            token = _make_token({"sub": "user-123"})
            result = await provider.verify_token(token)

        mock_registry.validate.assert_called_once_with(mock_token_obj.claims)
        assert result is True


# ---------------------------------------------------------------------------
# create_user_from_token
# ---------------------------------------------------------------------------


class TestCreateUserFromToken:
    @pytest.mark.asyncio
    async def test_uses_username_claim_when_present(self):
        provider = _fresh_provider()
        token = _make_token(
            {
                "sub": "user-1",
                "username": "johndoe",
                "email": "john@example.com",
            }
        )
        user = await provider.create_user_from_token(token)
        assert user.id == "user-1"
        assert user.name == "johndoe"
        assert user.email == "john@example.com"

    @pytest.mark.asyncio
    async def test_falls_back_to_preferred_username(self):
        provider = _fresh_provider()
        token = _make_token(
            {
                "sub": "user-2",
                "preferred_username": "jane",
            }
        )
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

        provider = _fresh_provider(groups_provider=groups_provider)
        token = _make_token({"sub": "user-5", "username": "u5"})
        user = await provider.create_user_from_token(token)
        assert await user.groups == ["admin", "staff"]

    @pytest.mark.asyncio
    async def test_returns_empty_groups_without_provider(self):
        provider = _fresh_provider()
        token = _make_token({"sub": "user-6", "username": "u6"})
        user = await provider.create_user_from_token(token)
        assert await user.groups == []
