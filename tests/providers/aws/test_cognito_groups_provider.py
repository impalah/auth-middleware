"""Unit tests for CognitoGroupsProvider."""

import pytest

from auth_middleware.contracts.groups_provider import GroupsProvider
from auth_middleware.providers.aws import COGNITO_GROUPS_CLAIM
from auth_middleware.providers.aws.cognito_groups_provider import CognitoGroupsProvider
from auth_middleware.types.jwt import JWTAuthorizationCredentials


@pytest.fixture
def provider() -> CognitoGroupsProvider:
    return CognitoGroupsProvider()


def _make_token(**claims) -> JWTAuthorizationCredentials:
    return JWTAuthorizationCredentials(
        jwt_token="tok",
        header={"alg": "HS256", "typ": "JWT"},
        claims=claims,
        signature="sig",
        message="msg",
    )


class TestCognitoGroupsProviderInheritance:
    def test_is_groups_provider(self, provider):
        assert isinstance(provider, GroupsProvider)


class TestFetchGroupsFromCognitoGroups:
    @pytest.mark.asyncio
    async def test_returns_groups_from_cognito_groups_claim(self, provider):
        token = _make_token(**{COGNITO_GROUPS_CLAIM: ["admin", "teachers"]})
        result = await provider.fetch_groups(token)
        assert result == ["admin", "teachers"]

    @pytest.mark.asyncio
    async def test_extracts_group_from_scope_when_no_groups_claim(self, provider):
        token = _make_token(scope="server-rsid/administrator")
        result = await provider.fetch_groups(token)
        assert result == ["administrator"]

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_groups_or_scope(self, provider):
        token = _make_token(sub="user-1", email="user@example.com")
        result = await provider.fetch_groups(token)
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_multi_scope_user_token(self, provider):
        # A real user access token's standard OAuth2 scope claim is a
        # space-separated list, not a single custom scope — it must not
        # be misread as one group.
        token = _make_token(scope="aws.cognito.signin.user.admin openid profile")
        result = await provider.fetch_groups(token)
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_plain_string_token(self, provider):
        result = await provider.fetch_groups("raw-string-token")
        assert result == []


class TestGroupsClaimOverride:
    @pytest.mark.asyncio
    async def test_uses_configured_groups_claim(self):
        provider = CognitoGroupsProvider(groups_claim="custom:groups")
        token = _make_token(**{"custom:groups": ["admin"]})
        result = await provider.fetch_groups(token)
        assert result == ["admin"]

    @pytest.mark.asyncio
    async def test_default_groups_claim_ignored_when_custom_configured(self):
        provider = CognitoGroupsProvider(groups_claim="custom:groups")
        token = _make_token(**{COGNITO_GROUPS_CLAIM: ["admin"]}, scope="pool/student")
        result = await provider.fetch_groups(token)
        assert result == ["student"]
