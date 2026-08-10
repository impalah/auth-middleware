"""Tests for OidcProvider (generic OIDC identity providers, e.g. Authentik,
Keycloak, Auth0)."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from joserfc.errors import JoseError

from auth_middleware.contracts.groups_provider import GroupsProvider
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.providers.oidc.oidc_exception import OidcException
from auth_middleware.providers.oidc.oidc_provider import OidcProvider
from auth_middleware.providers.oidc.oidc_provider_settings import OidcProviderSettings
from auth_middleware.providers.oidc.token_type import TokenType
from auth_middleware.types.jwt import JWKS, JWTAuthorizationCredentials

_MOCK_REQUEST = httpx.Request("GET", "http://test")
_ISSUER = "https://authentik.example.com/application/o/my-app/"


def _settings(**kwargs) -> OidcProviderSettings:
    base = {"issuer": _ISSUER}
    base.update(kwargs)
    return OidcProviderSettings(**base)


def _make_token(claims: dict) -> JWTAuthorizationCredentials:
    return JWTAuthorizationCredentials(
        jwt_token="h.p.s",
        header={"alg": "RS256", "kid": "k1"},
        claims=claims,
        signature="s",
        message="h.p",
    )


def _unexpired_claims(**extra) -> dict:
    base = {"iss": _ISSUER, "exp": int(time.time()) + 3600}
    base.update(extra)
    return base


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestOidcProviderInit:
    def test_rejects_non_oidc_settings(self):
        with pytest.raises(ValueError, match="OidcProviderSettings"):
            OidcProvider(settings=object())  # type: ignore[arg-type]

    def test_accepts_oidc_settings(self):
        provider = OidcProvider(settings=_settings())
        assert provider._jwks_uri is None

    def test_uses_explicit_jwks_uri_if_given(self):
        provider = OidcProvider(
            settings=_settings(jwks_uri="https://idp.example.com/jwks/")
        )
        assert provider._jwks_uri == "https://idp.example.com/jwks/"


# ---------------------------------------------------------------------------
# JWKS discovery + fetch
# ---------------------------------------------------------------------------


class TestDiscoveryAndKeys:
    @pytest.mark.asyncio
    async def test_discovers_jwks_uri_from_default_discovery_url(self):
        provider = OidcProvider(settings=_settings())

        discovery_response = httpx.Response(
            200,
            json={"jwks_uri": "https://authentik.example.com/app/jwks/"},
            request=_MOCK_REQUEST,
        )

        with patch(
            "auth_middleware.providers.oidc.oidc_provider.httpx.AsyncClient.get",
            return_value=discovery_response,
        ) as mock_get:
            jwks_uri = await provider._discover_jwks_uri()

        assert jwks_uri == "https://authentik.example.com/app/jwks/"
        mock_get.assert_awaited_once_with(
            "https://authentik.example.com/application/o/my-app"
            "/.well-known/openid-configuration"
        )

    @pytest.mark.asyncio
    async def test_discovery_url_override_is_used(self):
        provider = OidcProvider(
            settings=_settings(discovery_url="https://idp.example.com/custom")
        )
        discovery_response = httpx.Response(
            200,
            json={"jwks_uri": "https://idp.example.com/jwks/"},
            request=_MOCK_REQUEST,
        )

        with patch(
            "auth_middleware.providers.oidc.oidc_provider.httpx.AsyncClient.get",
            return_value=discovery_response,
        ) as mock_get:
            await provider._discover_jwks_uri()

        mock_get.assert_awaited_once_with("https://idp.example.com/custom")

    @pytest.mark.asyncio
    async def test_discovery_result_is_cached(self):
        provider = OidcProvider(settings=_settings())
        discovery_response = httpx.Response(
            200,
            json={"jwks_uri": "https://authentik.example.com/app/jwks/"},
            request=_MOCK_REQUEST,
        )

        with patch(
            "auth_middleware.providers.oidc.oidc_provider.httpx.AsyncClient.get",
            return_value=discovery_response,
        ) as mock_get:
            await provider._discover_jwks_uri()
            await provider._discover_jwks_uri()

        mock_get.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_skips_discovery_when_jwks_uri_configured(self):
        provider = OidcProvider(
            settings=_settings(jwks_uri="https://idp.example.com/jwks/")
        )

        with patch(
            "auth_middleware.providers.oidc.oidc_provider.httpx.AsyncClient.get",
        ) as mock_get:
            jwks_uri = await provider._discover_jwks_uri()

        assert jwks_uri == "https://idp.example.com/jwks/"
        mock_get.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_discovery_raises_on_http_error(self):
        provider = OidcProvider(settings=_settings())

        with patch(
            "auth_middleware.providers.oidc.oidc_provider.httpx.AsyncClient.get",
            return_value=httpx.Response(500, request=_MOCK_REQUEST),
        ):
            with pytest.raises(InvalidTokenException):
                await provider._discover_jwks_uri()

    @pytest.mark.asyncio
    async def test_discovery_raises_when_jwks_uri_missing_from_document(self):
        provider = OidcProvider(settings=_settings())

        with patch(
            "auth_middleware.providers.oidc.oidc_provider.httpx.AsyncClient.get",
            return_value=httpx.Response(200, json={}, request=_MOCK_REQUEST),
        ):
            with pytest.raises(OidcException, match="jwks_uri"):
                await provider._discover_jwks_uri()

    @pytest.mark.asyncio
    async def test_get_keys_fetches_from_discovered_uri(self):
        provider = OidcProvider(
            settings=_settings(jwks_uri="https://idp.example.com/jwks/")
        )

        with patch(
            "auth_middleware.providers.oidc.oidc_provider.httpx.AsyncClient.get",
            return_value=httpx.Response(
                200,
                json={"keys": [{"kid": "key1"}, {"kid": "key2"}]},
                request=_MOCK_REQUEST,
            ),
        ):
            keys = await provider.get_keys()

        assert len(keys) == 2
        assert keys[0]["kid"] == "key1"

    @pytest.mark.asyncio
    async def test_load_jwks_returns_cache_metadata(self):
        provider = OidcProvider(
            settings=_settings(
                jwks_uri="https://idp.example.com/jwks/",
                jwks_cache_interval=5,
                jwks_cache_usages=50,
            )
        )

        with patch(
            "auth_middleware.providers.oidc.oidc_provider.httpx.AsyncClient.get",
            return_value=httpx.Response(
                200, json={"keys": [{"kid": "key1"}]}, request=_MOCK_REQUEST
            ),
        ):
            jwks = await provider.load_jwks()

        assert isinstance(jwks, JWKS)
        assert jwks.keys == [{"kid": "key1"}]
        assert jwks.usage_counter == 50


# ---------------------------------------------------------------------------
# verify_token
# ---------------------------------------------------------------------------


class TestVerifyToken:
    @pytest.mark.asyncio
    async def test_raises_when_no_key_found(self):
        provider = OidcProvider(settings=_settings())
        provider._get_hmac_key = AsyncMock(return_value=None)
        token = _make_token(_unexpired_claims(sub="u1"))

        with pytest.raises(InvalidTokenException, match="No public key found"):
            await provider.verify_token(token)

    @pytest.mark.asyncio
    async def test_returns_true_when_verification_disabled(self):
        provider = OidcProvider(
            settings=_settings(jwt_token_verification_disabled=True)
        )
        token = _make_token({"sub": "u1"})

        assert await provider.verify_token(token) is True

    @pytest.mark.asyncio
    async def test_accepts_valid_token(self):
        provider = OidcProvider(settings=_settings(audience="my-client-id"))
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token(_unexpired_claims(sub="u1", aud="my-client-id"))

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            assert await provider.verify_token(token) is True

    @pytest.mark.asyncio
    async def test_rejects_wrong_audience(self):
        provider = OidcProvider(settings=_settings(audience="my-client-id"))
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token(_unexpired_claims(sub="u1", aud="someone-else"))

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            assert await provider.verify_token(token) is False

    @pytest.mark.asyncio
    async def test_rejects_wrong_issuer(self):
        provider = OidcProvider(settings=_settings())
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token(
            {
                "sub": "u1",
                "iss": "https://not-my-idp.example.com/",
                "exp": int(time.time()) + 3600,
            }
        )

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            assert await provider.verify_token(token) is False

    @pytest.mark.asyncio
    async def test_skips_audience_check_when_not_configured(self):
        provider = OidcProvider(settings=_settings())  # no audience configured
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token(_unexpired_claims(sub="u1", aud="whatever"))

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            assert await provider.verify_token(token) is True

    @pytest.mark.asyncio
    async def test_rejects_expired_token(self):
        provider = OidcProvider(settings=_settings())
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token(
            {"sub": "u1", "iss": _ISSUER, "exp": int(time.time()) - 3600}
        )

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            assert await provider.verify_token(token) is False

    @pytest.mark.asyncio
    async def test_accepts_recently_expired_token_within_leeway(self):
        provider = OidcProvider(settings=_settings(jwt_leeway=30))
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token({"sub": "u1", "iss": _ISSUER, "exp": int(time.time()) - 10})

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            assert await provider.verify_token(token) is True

    @pytest.mark.asyncio
    async def test_returns_false_on_bad_signature(self):
        provider = OidcProvider(settings=_settings())
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token(_unexpired_claims(sub="u1"))

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                side_effect=JoseError("bad signature"),
            ),
        ):
            assert await provider.verify_token(token) is False


# ---------------------------------------------------------------------------
# create_user_from_token
# ---------------------------------------------------------------------------


class TestCreateUserFromToken:
    @pytest.mark.asyncio
    async def test_extracts_groups_from_token_claim(self):
        provider = OidcProvider(settings=_settings())
        token = _make_token(
            _unexpired_claims(
                sub="u1",
                preferred_username="jdoe",
                email="jdoe@example.com",
                groups=["admins", "devs"],
            )
        )

        user = await provider.create_user_from_token(token)

        assert user.id == "u1"
        assert user.name == "jdoe"
        assert user.email == "jdoe@example.com"
        assert await user.groups == ["admins", "devs"]

    @pytest.mark.asyncio
    async def test_uses_groups_provider_when_claim_absent(self):
        mock_groups = MagicMock(spec=GroupsProvider)
        mock_groups.fetch_groups = AsyncMock(return_value=["from-db"])
        provider = OidcProvider(settings=_settings(), groups_provider=mock_groups)
        token = _make_token(_unexpired_claims(sub="u1"))

        user = await provider.create_user_from_token(token)

        mock_groups.fetch_groups.assert_awaited_once_with(token)
        assert await user.groups == ["from-db"]

    @pytest.mark.asyncio
    async def test_groups_provider_takes_precedence_over_claim_when_both_present(self):
        # An explicitly configured GroupsProvider is authoritative, even if
        # the token also carries a (possibly stale) groups claim.
        mock_groups = MagicMock(spec=GroupsProvider)
        mock_groups.fetch_groups = AsyncMock(return_value=["from-db"])
        provider = OidcProvider(settings=_settings(), groups_provider=mock_groups)
        token = _make_token(_unexpired_claims(sub="u1", groups=["from-claim"]))

        user = await provider.create_user_from_token(token)

        mock_groups.fetch_groups.assert_awaited_once_with(token)
        assert await user.groups == ["from-db"]

    @pytest.mark.asyncio
    async def test_groups_claim_none_disables_claim_reading_without_provider(self):
        provider = OidcProvider(settings=_settings(groups_claim=None))
        token = _make_token(_unexpired_claims(sub="u1", groups=["ignored"]))

        user = await provider.create_user_from_token(token)

        # groups_claim=None means "don't read groups from the token claims";
        # no groups_provider was configured either, so groups stay empty.
        assert await user.groups == []

    @pytest.mark.asyncio
    async def test_falls_back_to_sub_when_username_claim_missing(self):
        provider = OidcProvider(settings=_settings())
        token = _make_token(_unexpired_claims(sub="u1"))

        user = await provider.create_user_from_token(token)

        assert user.name == "u1"
        assert user.email is None

    @pytest.mark.asyncio
    async def test_uses_custom_username_claim(self):
        provider = OidcProvider(settings=_settings(username_claim="upn"))
        token = _make_token(_unexpired_claims(sub="u1", upn="jdoe@corp.example.com"))

        user = await provider.create_user_from_token(token)

        assert user.name == "jdoe@corp.example.com"

    @pytest.mark.asyncio
    async def test_uses_username_claim_fallback_when_primary_absent(self):
        provider = OidcProvider(
            settings=_settings(
                username_claim="username", username_claim_fallbacks=["cognito:username"]
            )
        )
        token = _make_token(_unexpired_claims(sub="u1", **{"cognito:username": "jdoe"}))

        user = await provider.create_user_from_token(token)

        assert user.name == "jdoe"

    @pytest.mark.asyncio
    async def test_prefers_primary_username_claim_over_fallback(self):
        provider = OidcProvider(
            settings=_settings(
                username_claim="username", username_claim_fallbacks=["cognito:username"]
            )
        )
        token = _make_token(
            _unexpired_claims(
                sub="u1", username="jdoe-access", **{"cognito:username": "jdoe-id"}
            )
        )

        user = await provider.create_user_from_token(token)

        assert user.name == "jdoe-access"

    @pytest.mark.asyncio
    async def test_falls_back_to_email_when_all_username_claims_absent(self):
        provider = OidcProvider(
            settings=_settings(
                username_claim="username", username_claim_fallbacks=["cognito:username"]
            )
        )
        token = _make_token(_unexpired_claims(sub="u1", email="jdoe@example.com"))

        user = await provider.create_user_from_token(token)

        assert user.name == "jdoe@example.com"


# ---------------------------------------------------------------------------
# Token type detection
# ---------------------------------------------------------------------------


class TestDetectTokenType:
    def test_explicit_token_use_claim_id(self):
        provider = OidcProvider(settings=_settings())
        assert provider._detect_token_type({"token_use": "id"}) == TokenType.ID

    def test_explicit_token_use_claim_access(self):
        provider = OidcProvider(settings=_settings())
        assert provider._detect_token_type({"token_use": "access"}) == TokenType.ACCESS

    def test_explicit_token_use_claim_refresh(self):
        provider = OidcProvider(settings=_settings())
        assert (
            provider._detect_token_type({"token_use": "refresh"}) == TokenType.REFRESH
        )

    def test_unrecognized_token_use_falls_back_to_heuristic(self):
        provider = OidcProvider(settings=_settings())
        claims = {"token_use": "something-weird", "email": "jdoe@example.com"}
        assert provider._detect_token_type(claims) == TokenType.ID

    def test_heuristic_identity_claim_means_id_token(self):
        provider = OidcProvider(settings=_settings())
        claims = {"sub": "u1", "preferred_username": "jdoe"}
        assert provider._detect_token_type(claims) == TokenType.ID

    def test_heuristic_client_id_without_identity_means_access_token(self):
        provider = OidcProvider(settings=_settings())
        claims = {"sub": "u1", "client_id": "svc-account"}
        assert provider._detect_token_type(claims) == TokenType.ACCESS

    def test_heuristic_no_signal_means_unknown(self):
        provider = OidcProvider(settings=_settings())
        claims = {"sub": "u1"}
        assert provider._detect_token_type(claims) == TokenType.UNKNOWN

    def test_token_use_claim_disabled_always_uses_heuristic(self):
        provider = OidcProvider(settings=_settings(token_use_claim=None))
        claims = {"token_use": "id", "sub": "u1", "client_id": "svc-account"}
        assert provider._detect_token_type(claims) == TokenType.ACCESS

    def test_cognito_style_access_token_detected_via_username_identity_claim(self):
        # Real Cognito access token: token_use="access" but carries
        # "username" (not "preferred_username"/"email") for real users.
        provider = OidcProvider(settings=_settings())
        claims = {
            "sub": "u1",
            "token_use": "access",
            "client_id": "cognito-client",
            "username": "jdoe",
        }
        assert provider._detect_token_type(claims) == TokenType.ACCESS
        assert not provider._is_m2m_token(claims, TokenType.ACCESS)


class TestM2mDetection:
    def test_access_token_without_identity_claims_is_m2m(self):
        provider = OidcProvider(settings=_settings())
        claims = {"sub": "svc-account", "client_id": "svc-account"}
        token_type = provider._detect_token_type(claims)
        assert token_type == TokenType.ACCESS
        assert provider._is_m2m_token(claims, token_type) is True

    def test_access_token_with_identity_claim_is_not_m2m(self):
        provider = OidcProvider(settings=_settings())
        claims = {
            "sub": "u1",
            "token_use": "access",
            "client_id": "app",
            "email": "jdoe@example.com",
        }
        token_type = provider._detect_token_type(claims)
        assert provider._is_m2m_token(claims, token_type) is False

    def test_id_token_is_never_m2m(self):
        provider = OidcProvider(settings=_settings())
        claims = {"sub": "u1", "preferred_username": "jdoe"}
        token_type = provider._detect_token_type(claims)
        assert provider._is_m2m_token(claims, token_type) is False

    def test_m2m_detection_can_be_disabled(self):
        provider = OidcProvider(settings=_settings(detect_m2m_tokens=False))
        claims = {"sub": "svc-account", "client_id": "svc-account"}
        token_type = provider._detect_token_type(claims)
        assert provider._is_m2m_token(claims, token_type) is False

    @pytest.mark.asyncio
    async def test_m2m_token_skips_groups_and_roles_providers(self):
        mock_groups = MagicMock(spec=GroupsProvider)
        mock_groups.fetch_groups = AsyncMock(return_value=["should-not-be-called"])
        provider = OidcProvider(settings=_settings(), groups_provider=mock_groups)
        token = _make_token(
            _unexpired_claims(sub="svc-account", client_id="svc-account")
        )

        user = await provider.create_user_from_token(token)

        mock_groups.fetch_groups.assert_not_called()
        assert user.is_m2m is True
        assert user.client_id == "svc-account"
        assert await user.groups == []

    @pytest.mark.asyncio
    async def test_regular_user_token_is_not_flagged_as_m2m(self):
        provider = OidcProvider(settings=_settings())
        token = _make_token(_unexpired_claims(sub="u1", preferred_username="jdoe"))

        user = await provider.create_user_from_token(token)

        assert user.is_m2m is False
        assert user.client_id is None

    @pytest.mark.asyncio
    async def test_m2m_token_without_sub_falls_back_to_client_id_as_user_id(self):
        provider = OidcProvider(settings=_settings())
        token = _make_token(
            {
                "iss": _ISSUER,
                "exp": int(time.time()) + 3600,
                "client_id": "svc-account",
            }
        )

        user = await provider.create_user_from_token(token)

        assert user.id == "svc-account"
        assert user.is_m2m is True

    @pytest.mark.asyncio
    async def test_raises_when_no_sub_and_no_client_id(self):
        provider = OidcProvider(settings=_settings())
        token = _make_token(_unexpired_claims())

        with pytest.raises(OidcException, match="sub"):
            await provider.create_user_from_token(token)


# ---------------------------------------------------------------------------
# Cognito-style tokens through OidcProvider (no 'aud', 'client_id' instead)
# ---------------------------------------------------------------------------


class TestCognitoStyleTokensViaOidcProvider:
    @pytest.mark.asyncio
    async def test_accepts_access_token_with_client_id_instead_of_aud(self):
        provider = OidcProvider(settings=_settings(audience="my-app-client"))
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token(
            _unexpired_claims(
                sub="u1",
                token_use="access",
                client_id="my-app-client",
                username="jdoe",
            )
        )

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            assert await provider.verify_token(token) is True

    @pytest.mark.asyncio
    async def test_rejects_access_token_with_wrong_client_id(self):
        provider = OidcProvider(settings=_settings(audience="my-app-client"))
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token(
            _unexpired_claims(
                sub="u1", token_use="access", client_id="someone-elses-client"
            )
        )

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            assert await provider.verify_token(token) is False

    @pytest.mark.asyncio
    async def test_rejects_refresh_token_used_as_bearer_credential(self):
        provider = OidcProvider(settings=_settings())
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        token = _make_token(_unexpired_claims(sub="u1", token_use="refresh"))

        with (
            patch(
                "auth_middleware.providers.oidc.oidc_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.oidc.oidc_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            assert await provider.verify_token(token) is False
