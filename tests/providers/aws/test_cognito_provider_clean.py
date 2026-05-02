"""Tests for _resolve_provider helper and uncovered CognitoProvider branches."""

from unittest.mock import AsyncMock, MagicMock

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
    """Return a CognitoProvider, resetting the per-class singleton first."""
    CognitoProvider._instances.pop(CognitoProvider, None)
    return CognitoProvider(settings=_settings(), **kwargs)


def _make_token(claims: dict) -> JWTAuthorizationCredentials:
    return JWTAuthorizationCredentials(
        jwt_token="h.p.s",
        header={"alg": "RS256", "kid": "k1"},
        claims=claims,
        signature="s",
        message="h.p",
    )


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
    def setup_method(self):
        CognitoProvider._instances.pop(CognitoProvider, None)

    def test_raises_when_settings_is_none(self):
        with pytest.raises(ValueError, match="Settings must be provided"):
            CognitoProvider(settings=None)

    def test_singleton_reuses_instance(self):
        p1 = _fresh_provider()
        # Second call returns the same object, even with different args
        p2 = CognitoProvider(settings=_settings())
        assert p1 is p2

    def test_initialised_flag_set(self):
        provider = _fresh_provider()
        assert provider._initialized is True


# ---------------------------------------------------------------------------
# get_keys — missing branches
# ---------------------------------------------------------------------------


class TestGetKeys:
    def setup_method(self):
        CognitoProvider._instances.pop(CognitoProvider, None)

    @pytest.mark.asyncio
    async def test_raises_when_jwks_url_template_is_none(self):
        settings = CognitoAuthzProviderSettings(
            user_pool_region="us-east-1",
            user_pool_id="us-east-1_Test",
            jwks_url_template=None,
        )
        CognitoProvider._instances.pop(CognitoProvider, None)
        provider = CognitoProvider(settings=settings)
        with pytest.raises(ValueError, match="jwks_url_template"):
            await provider.get_keys()


# ---------------------------------------------------------------------------
# verify_token — jwt_token_verification_disabled branch
# ---------------------------------------------------------------------------


class TestVerifyTokenDisabled:
    def setup_method(self):
        CognitoProvider._instances.pop(CognitoProvider, None)

    @pytest.mark.asyncio
    async def test_returns_true_when_verification_disabled(self):
        settings = _settings(jwt_token_verification_disabled=True)
        CognitoProvider._instances.pop(CognitoProvider, None)
        provider = CognitoProvider(settings=settings)
        token = _make_token({"sub": "u1"})
        result = await provider.verify_token(token)
        assert result is True


# ---------------------------------------------------------------------------
# create_user_from_token — groups_provider and roles_provider branches
# ---------------------------------------------------------------------------


class TestCreateUserFromTokenProviders:
    def setup_method(self):
        CognitoProvider._instances.pop(CognitoProvider, None)

    @pytest.mark.asyncio
    async def test_fetches_groups_for_non_m2m_token(self):
        mock_groups = MagicMock(spec=GroupsProvider)
        mock_groups.fetch_groups = AsyncMock(return_value=["admin"])

        CognitoProvider._instances.pop(CognitoProvider, None)
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

        CognitoProvider._instances.pop(CognitoProvider, None)
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
        CognitoProvider._instances.pop(CognitoProvider, None)
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
        CognitoProvider._instances.pop(CognitoProvider, None)
        provider = CognitoProvider(settings=_settings())

        token = _make_token({"sub": "u3"})
        user = await provider.create_user_from_token(token)
        assert user.name == "u3"
