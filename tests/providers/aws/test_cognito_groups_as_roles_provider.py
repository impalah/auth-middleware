"""
Unit tests for CognitoGroupsAsRolesProvider.
"""

import pytest

from auth_middleware.contracts.roles_provider import RolesProvider
from auth_middleware.providers.aws import COGNITO_GROUPS_CLAIM
from auth_middleware.providers.aws.cognito_groups_as_roles_provider import (
    CognitoGroupsAsRolesProvider,
)
from auth_middleware.types.jwt import JWTAuthorizationCredentials


@pytest.fixture
def provider() -> CognitoGroupsAsRolesProvider:
    return CognitoGroupsAsRolesProvider()


def _make_token(**claims) -> JWTAuthorizationCredentials:
    return JWTAuthorizationCredentials(
        jwt_token="tok",
        header={"alg": "HS256", "typ": "JWT"},
        claims=claims,
        signature="sig",
        message="msg",
    )


class TestCognitoGroupsAsRolesProviderInheritance:
    def test_is_roles_provider(self, provider):
        assert isinstance(provider, RolesProvider)

    def test_implements_fetch_roles(self, provider):
        assert callable(provider.fetch_roles)


class TestFetchRolesFromCognitoGroups:
    @pytest.mark.asyncio
    async def test_returns_groups_from_cognito_groups_claim(self, provider):
        token = _make_token(**{COGNITO_GROUPS_CLAIM: ["admin", "teachers"]})
        result = await provider.fetch_roles(token)
        assert result == ["admin", "teachers"]

    @pytest.mark.asyncio
    async def test_returns_single_group(self, provider):
        token = _make_token(**{COGNITO_GROUPS_CLAIM: ["student"]})
        result = await provider.fetch_roles(token)
        assert result == ["student"]

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_groups_empty(self, provider):
        token = _make_token(**{COGNITO_GROUPS_CLAIM: []})
        result = await provider.fetch_roles(token)
        assert result == []


class TestFetchRolesFromScope:
    """The scope claim maps only when the application says which scopes count."""

    @pytest.mark.asyncio
    async def test_scope_is_ignored_by_default(self, provider):
        token = _make_token(scope="server-rsid/administrator")
        assert await provider.fetch_roles(token) == []

    @pytest.mark.asyncio
    async def test_resource_server_maps_its_own_scope(self):
        provider = CognitoGroupsAsRolesProvider(resource_server="server-rsid")
        token = _make_token(scope="server-rsid/administrator")
        assert await provider.fetch_roles(token) == ["administrator"]

    @pytest.mark.asyncio
    async def test_another_resource_servers_scope_never_becomes_a_role(self):
        provider = CognitoGroupsAsRolesProvider(resource_server="server-rsid")
        assert await provider.fetch_roles(_make_token(scope="other-api/admin")) == []
        assert await provider.fetch_roles(_make_token(scope="server-rsidX/admin")) == []
        assert await provider.fetch_roles(_make_token(scope="admin")) == []

    @pytest.mark.asyncio
    async def test_scope_map_is_exact(self):
        provider = CognitoGroupsAsRolesProvider(
            scope_map={"server-rsid/read": "reader"}
        )
        assert await provider.fetch_roles(_make_token(scope="server-rsid/read")) == [
            "reader"
        ]
        assert await provider.fetch_roles(_make_token(scope="server-rsid/write")) == []

    @pytest.mark.asyncio
    async def test_cognito_groups_takes_precedence_over_scope(self):
        provider = CognitoGroupsAsRolesProvider(resource_server="server-rsid")
        token = _make_token(
            **{COGNITO_GROUPS_CLAIM: ["admin"]},
            scope="server-rsid/student",
        )
        assert await provider.fetch_roles(token) == ["admin"]


class TestGroupsClaimOverride:
    @pytest.mark.asyncio
    async def test_uses_configured_groups_claim(self):
        provider = CognitoGroupsAsRolesProvider(groups_claim="custom:groups")
        token = _make_token(**{"custom:groups": ["admin"]})
        result = await provider.fetch_roles(token)
        assert result == ["admin"]

    @pytest.mark.asyncio
    async def test_default_groups_claim_ignored_when_custom_configured(self):
        provider = CognitoGroupsAsRolesProvider(
            groups_claim="custom:groups", resource_server="pool"
        )
        token = _make_token(**{COGNITO_GROUPS_CLAIM: ["admin"]}, scope="pool/student")
        result = await provider.fetch_roles(token)
        assert result == ["student"]


class TestFetchRolesEdgeCases:
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_groups_or_scope(self, provider):
        token = _make_token(sub="user-1", email="user@example.com")
        result = await provider.fetch_roles(token)
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_multi_scope_user_token(self, provider):
        # A real user access token's standard OAuth2 scope claim is a
        # space-separated list, not a single custom scope — it must not
        # be misread as one role.
        token = _make_token(scope="aws.cognito.signin.user.admin openid profile")
        result = await provider.fetch_roles(token)
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_plain_string_token(self, provider):
        result = await provider.fetch_roles("raw-string-token")
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_none_coerced_input(self, provider):
        # Passing a non-JWTAuthorizationCredentials value
        result = await provider.fetch_roles(object())
        assert result == []
