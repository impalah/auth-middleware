"""
Unit tests for CognitoGroupsAsRolesProvider.
"""

import pytest

from auth_middleware.providers.authz.cognito_groups_as_roles_provider import (
    CognitoGroupsAsRolesProvider,
)
from auth_middleware.providers.authz.roles_provider import RolesProvider
from auth_middleware.providers.cognito import COGNITO_GROUPS_CLAIM
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
    @pytest.mark.asyncio
    async def test_extracts_role_from_scope_when_no_groups_claim(self, provider):
        token = _make_token(scope="server-rsid/administrator")
        result = await provider.fetch_roles(token)
        assert result == ["administrator"]

    @pytest.mark.asyncio
    async def test_extracts_role_from_scope_simple(self, provider):
        token = _make_token(scope="mypool/student")
        result = await provider.fetch_roles(token)
        assert result == ["student"]

    @pytest.mark.asyncio
    async def test_scope_without_slash_returns_whole_value(self, provider):
        token = _make_token(scope="teacher")
        result = await provider.fetch_roles(token)
        assert result == ["teacher"]

    @pytest.mark.asyncio
    async def test_cognito_groups_takes_precedence_over_scope(self, provider):
        token = _make_token(
            **{COGNITO_GROUPS_CLAIM: ["admin"]},
            scope="server-rsid/student",
        )
        result = await provider.fetch_roles(token)
        assert result == ["admin"]


class TestFetchRolesEdgeCases:
    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_groups_or_scope(self, provider):
        token = _make_token(sub="user-1", email="user@example.com")
        result = await provider.fetch_roles(token)
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_plain_string_token(self, provider):
        result = await provider.fetch_roles("raw-string-token")
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_none_coerced_input(self, provider):
        # Passing a non-JWTAuthorizationCredentials value
        result = await provider.fetch_roles(object())  # type: ignore[arg-type]
        assert result == []
