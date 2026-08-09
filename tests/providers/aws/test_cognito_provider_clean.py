"""Tests for _resolve_provider helper and uncovered CognitoProvider branches."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth_middleware.contracts.groups_provider import GroupsProvider
from auth_middleware.providers.aws.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.aws.cognito_groups_provider import (
    CognitoGroupsProvider,
)
from auth_middleware.providers.aws.cognito_provider import (
    CognitoProvider,
    _resolve_provider,
)
from auth_middleware.types.jwt import JWTAuthorizationCredentials

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _settings(**kwargs):
    base = dict(
        user_pool_region="us-east-1",
        user_pool_id="us-east-1_Test",
        jwks_url_template="https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
    )
    base.update(kwargs)
    return CognitoAuthzProviderSettings(**base)


def _fresh_provider(**kwargs):
    """Return a new CognitoProvider (no shared singleton state to reset)."""
    return CognitoProvider(settings=_settings(), **kwargs)


def _make_token(claims: dict) -> JWTAuthorizationCredentials:
    return JWTAuthorizationCredentials(
        jwt_token="h.p.s",
        header={"alg": "RS256", "kid": "k1"},
        claims=claims,
        signature="s",
        message="h.p",
    )


def _unexpired_claims(**extra) -> dict:
    """Claims with a non-expired 'exp', for tests that aren't about expiration."""
    return {"exp": int(time.time()) + 3600, **extra}


# ---------------------------------------------------------------------------
# _resolve_provider
# ---------------------------------------------------------------------------


class TestResolveProvider:
    def test_returns_none_when_provider_is_none(self):
        result = _resolve_provider(None, GroupsProvider)
        assert result is None

    def test_instantiates_provider_class(self):
        result = _resolve_provider(CognitoGroupsProvider, GroupsProvider)
        assert isinstance(result, CognitoGroupsProvider)

    def test_returns_instance_as_is(self):
        instance = CognitoGroupsProvider()
        result = _resolve_provider(instance, GroupsProvider)
        assert result is instance

    def test_allow_missing_returns_none_for_invalid_provider(self):
        result = _resolve_provider("not_a_provider", GroupsProvider, allow_missing=True)
        assert result is None

    def test_raises_value_error_for_invalid_provider_without_allow_missing(self):
        with pytest.raises(ValueError, match="GroupsProvider"):
            _resolve_provider("not_a_provider", GroupsProvider, allow_missing=False)


# ---------------------------------------------------------------------------
# CognitoProvider.__init__ edge cases
# ---------------------------------------------------------------------------


class TestCognitoProviderInit:
    def test_raises_when_settings_is_none(self):
        with pytest.raises(ValueError, match="Settings must be provided"):
            CognitoProvider(settings=None)

    def test_creates_independent_instances(self):
        """Each instantiation is independent — there is no shared singleton
        state that could silently ignore a later call's settings (a real
        bug this used to have: a second CognitoProvider(settings=...) call
        used to reuse the first instance and drop the new settings)."""
        p1 = CognitoProvider(settings=_settings(user_pool_id="pool-a"))
        p2 = CognitoProvider(settings=_settings(user_pool_id="pool-b"))

        assert p1 is not p2
        assert p1._settings.user_pool_id == "pool-a"
        assert p2._settings.user_pool_id == "pool-b"


# ---------------------------------------------------------------------------
# get_keys — missing branches
# ---------------------------------------------------------------------------


class TestGetKeys:
    @pytest.mark.asyncio
    async def test_raises_when_jwks_url_template_is_none(self):
        settings = CognitoAuthzProviderSettings(
            user_pool_region="us-east-1",
            user_pool_id="us-east-1_Test",
            jwks_url_template=None,
        )
        provider = CognitoProvider(settings=settings)
        with pytest.raises(ValueError, match="jwks_url_template"):
            await provider.get_keys()


# ---------------------------------------------------------------------------
# verify_token — jwt_token_verification_disabled branch
# ---------------------------------------------------------------------------


class TestVerifyTokenDisabled:
    @pytest.mark.asyncio
    async def test_returns_true_when_verification_disabled(self):
        settings = _settings(jwt_token_verification_disabled=True)
        provider = CognitoProvider(settings=settings)
        token = _make_token({"sub": "u1"})
        result = await provider.verify_token(token)
        assert result is True


# ---------------------------------------------------------------------------
# verify_token — client_id/aud validation (signature alone is not enough:
# any token signed by the user pool, for any app client, must be rejected
# unless it was issued for the configured user_pool_client_id)
# ---------------------------------------------------------------------------


class TestVerifyTokenClientId:
    @staticmethod
    def _provider_with_signature_ok(**settings_kwargs):
        """A CognitoProvider whose signature check always succeeds, so tests
        only exercise the client_id/aud branch."""
        provider = CognitoProvider(settings=_settings(**settings_kwargs))
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        return provider

    @pytest.mark.asyncio
    async def test_rejects_token_from_a_different_app_client_via_aud(self):
        provider = self._provider_with_signature_ok(
            user_pool_client_id="expected_client_id"
        )
        token = _make_token(_unexpired_claims(sub="u1", aud="other_client_id"))

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is False

    @pytest.mark.asyncio
    async def test_rejects_access_token_from_a_different_app_client_via_client_id(self):
        # Access tokens carry the app client id in "client_id", not "aud".
        provider = self._provider_with_signature_ok(
            user_pool_client_id="expected_client_id"
        )
        token = _make_token(
            _unexpired_claims(sub="u1", token_use="access", client_id="other_client_id")
        )

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is False

    @pytest.mark.asyncio
    async def test_accepts_id_token_matching_configured_client_id(self):
        provider = self._provider_with_signature_ok(
            user_pool_client_id="expected_client_id"
        )
        token = _make_token(_unexpired_claims(sub="u1", aud="expected_client_id"))

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is True

    @pytest.mark.asyncio
    async def test_accepts_access_token_matching_configured_client_id(self):
        provider = self._provider_with_signature_ok(
            user_pool_client_id="expected_client_id"
        )
        token = _make_token(
            _unexpired_claims(
                sub="u1", token_use="access", client_id="expected_client_id"
            )
        )

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is True

    @pytest.mark.asyncio
    async def test_skips_check_when_no_user_pool_client_id_configured(self):
        # Backward compatibility: if the app didn't configure
        # user_pool_client_id, signature validation alone still governs.
        provider = self._provider_with_signature_ok()
        token = _make_token(_unexpired_claims(sub="u1", aud="whatever_client_id"))

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is True


# ---------------------------------------------------------------------------
# verify_token — exp validation (a verified signature alone does not prove
# the token hasn't expired; joserfc's decode() never checks registered
# claims like exp/nbf/iat unless told to)
# ---------------------------------------------------------------------------


class TestVerifyTokenExpiration:
    @staticmethod
    def _provider_with_signature_ok(**settings_kwargs):
        provider = CognitoProvider(settings=_settings(**settings_kwargs))
        provider._get_hmac_key = AsyncMock(return_value={"kid": "k1"})
        return provider

    @pytest.mark.asyncio
    async def test_rejects_expired_token(self):
        provider = self._provider_with_signature_ok()
        token = _make_token({"sub": "u1", "exp": int(time.time()) - 3600})

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is False

    @pytest.mark.asyncio
    async def test_rejects_token_missing_exp_claim(self):
        provider = self._provider_with_signature_ok()
        token = _make_token({"sub": "u1"})

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is False

    @pytest.mark.asyncio
    async def test_accepts_token_with_future_exp(self):
        provider = self._provider_with_signature_ok()
        token = _make_token(_unexpired_claims(sub="u1"))

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is True

    @pytest.mark.asyncio
    async def test_rejects_recently_expired_token_with_no_leeway(self):
        provider = self._provider_with_signature_ok(jwt_leeway=0)
        token = _make_token({"sub": "u1", "exp": int(time.time()) - 10})

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is False

    @pytest.mark.asyncio
    async def test_accepts_recently_expired_token_within_leeway(self):
        provider = self._provider_with_signature_ok(jwt_leeway=30)
        token = _make_token({"sub": "u1", "exp": int(time.time()) - 10})

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is True

    @pytest.mark.asyncio
    async def test_still_rejects_token_expired_beyond_leeway(self):
        provider = self._provider_with_signature_ok(jwt_leeway=30)
        token = _make_token({"sub": "u1", "exp": int(time.time()) - 3600})

        with (
            patch(
                "auth_middleware.providers.aws.cognito_provider.import_key",
                return_value=MagicMock(),
            ),
            patch(
                "auth_middleware.providers.aws.cognito_provider.joserfc_jwt.decode",
                return_value=MagicMock(),
            ),
        ):
            result = await provider.verify_token(token)

        assert result is False


# ---------------------------------------------------------------------------
# create_user_from_token — groups_provider and roles_provider branches
# ---------------------------------------------------------------------------


class TestCreateUserFromTokenProviders:
    @pytest.mark.asyncio
    async def test_fetches_groups_for_non_m2m_token(self):
        mock_groups = MagicMock(spec=GroupsProvider)
        mock_groups.fetch_groups = AsyncMock(return_value=["admin"])

        provider = CognitoProvider(settings=_settings(), groups_provider=mock_groups)

        token = _make_token(
            {
                "sub": "u1",
                "username": "alice",
                "token_use": "id",  # not client_credentials → not M2M
            }
        )

        user = await provider.create_user_from_token(token)

        mock_groups.fetch_groups.assert_awaited_once_with(token)
        assert await user.groups == ["admin"]

    @pytest.mark.asyncio
    async def test_skips_groups_for_m2m_token(self):
        mock_groups = MagicMock(spec=GroupsProvider)
        mock_groups.fetch_groups = AsyncMock(return_value=["admin"])

        provider = CognitoProvider(settings=_settings(), groups_provider=mock_groups)

        # M2M tokens have client_credentials grant / "client_id" claim
        token = _make_token(
            {
                "sub": "client-abc",
                "client_id": "client-abc",
                "token_use": "access",
            }
        )

        user = await provider.create_user_from_token(token)

        # groups provider should NOT be called for M2M
        mock_groups.fetch_groups.assert_not_awaited()
        assert user.is_m2m is True

    @pytest.mark.asyncio
    async def test_creates_user_with_email_and_cognito_username_claim(self):
        provider = CognitoProvider(settings=_settings())

        token = _make_token(
            {
                "sub": "u2",
                "cognito:username": "bob",
                "email": "bob@example.com",
            }
        )

        user = await provider.create_user_from_token(token)
        assert user.name == "bob"
        assert user.email == "bob@example.com"

    @pytest.mark.asyncio
    async def test_falls_back_to_sub_when_no_name_claim(self):
        provider = CognitoProvider(settings=_settings())

        token = _make_token({"sub": "u3"})
        user = await provider.create_user_from_token(token)
        assert user.name == "u3"
