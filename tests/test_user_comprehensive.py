"""Tests for User async properties (groups, permissions, roles, profile)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from auth_middleware.types.user import User


class TestUserGroupsProperty:
    @pytest.mark.asyncio
    async def test_groups_returns_injected_groups(self):
        """Groups passed in constructor are returned directly."""
        user = User(id="u1", name="Alice", groups=["admin", "staff"])
        result = await user.groups
        assert result == ["admin", "staff"]

    @pytest.mark.asyncio
    async def test_groups_returns_empty_without_provider(self):
        """No provider and no direct groups → empty list."""
        user = User(id="u2", name="Bob")
        result = await user.groups
        assert result == []

    @pytest.mark.asyncio
    async def test_groups_uses_provider_when_set(self):
        mock_provider = MagicMock()
        mock_provider.fetch_groups = AsyncMock(return_value=["viewer"])
        user = User(id="u3", name="Carol", token="tok", groups_provider=mock_provider)
        result = await user.groups
        assert result == ["viewer"]

    @pytest.mark.asyncio
    async def test_groups_cached_after_first_call(self):
        """Second call should not re-fetch."""
        mock_provider = MagicMock()
        mock_provider.fetch_groups = AsyncMock(return_value=["editor"])
        user = User(id="u4", name="Dave", token="tok", groups_provider=mock_provider)
        await user.groups
        await user.groups
        assert mock_provider.fetch_groups.call_count == 1

    @pytest.mark.asyncio
    async def test_groups_empty_when_provider_but_no_token(self):
        mock_provider = MagicMock()
        mock_provider.fetch_groups = AsyncMock(return_value=["admin"])
        # No token passed → _load_groups returns []
        user = User(id="u5", name="Eve", groups_provider=mock_provider)
        result = await user.groups
        assert result == []
        mock_provider.fetch_groups.assert_not_called()


class TestUserPermissionsProperty:
    @pytest.mark.asyncio
    async def test_permissions_returns_empty_without_provider(self):
        user = User(id="u1", name="Alice")
        result = await user.permissions
        assert result == []

    @pytest.mark.asyncio
    async def test_permissions_uses_provider(self):
        mock_provider = MagicMock()
        mock_provider.fetch_permissions = AsyncMock(return_value=["read", "write"])
        user = User(id="u2", name="Bob", token="tok", permissions_provider=mock_provider)
        result = await user.permissions
        assert result == ["read", "write"]

    @pytest.mark.asyncio
    async def test_permissions_cached_after_first_call(self):
        mock_provider = MagicMock()
        mock_provider.fetch_permissions = AsyncMock(return_value=["admin"])
        user = User(id="u3", name="Carol", token="tok", permissions_provider=mock_provider)
        await user.permissions
        await user.permissions
        assert mock_provider.fetch_permissions.call_count == 1

    @pytest.mark.asyncio
    async def test_permissions_empty_when_provider_but_no_token(self):
        mock_provider = MagicMock()
        mock_provider.fetch_permissions = AsyncMock(return_value=["write"])
        user = User(id="u4", name="Dave", permissions_provider=mock_provider)
        result = await user.permissions
        assert result == []
        mock_provider.fetch_permissions.assert_not_called()


class TestUserProfileProperty:
    @pytest.mark.asyncio
    async def test_profile_returns_empty_without_provider(self):
        user = User(id="u1", name="Alice")
        result = await user.profile
        assert result == {}

    @pytest.mark.asyncio
    async def test_profile_uses_provider(self):
        mock_provider = MagicMock()
        mock_provider.fetch_profile = AsyncMock(return_value={"first_name": "Alice"})
        user = User(id="u2", name="Alice", profile_provider=mock_provider)
        result = await user.profile
        assert result == {"first_name": "Alice"}

    @pytest.mark.asyncio
    async def test_profile_cached_after_first_call(self):
        mock_provider = MagicMock()
        mock_provider.fetch_profile = AsyncMock(return_value={"lang": "en"})
        user = User(id="u3", name="Charlie", profile_provider=mock_provider)
        await user.profile
        await user.profile
        assert mock_provider.fetch_profile.call_count == 1


class TestUserRolesProperty:
    @pytest.mark.asyncio
    async def test_roles_returns_injected_roles(self):
        """Roles passed in constructor are returned directly."""
        user = User(id="u1", name="Alice", roles=["admin", "editor"])
        result = await user.roles
        assert result == ["admin", "editor"]

    @pytest.mark.asyncio
    async def test_roles_returns_empty_without_provider(self):
        user = User(id="u2", name="Bob")
        result = await user.roles
        assert result == []

    @pytest.mark.asyncio
    async def test_roles_uses_provider_when_set(self):
        from auth_middleware.providers.authz.roles_provider import RolesProvider
        mock_provider = MagicMock(spec=RolesProvider)
        mock_provider.fetch_roles = AsyncMock(return_value=["moderator"])
        user = User(id="u3", name="Carol", token="tok", roles_provider=mock_provider)
        result = await user.roles
        assert result == ["moderator"]

    @pytest.mark.asyncio
    async def test_roles_cached_after_first_call(self):
        from auth_middleware.providers.authz.roles_provider import RolesProvider
        mock_provider = MagicMock(spec=RolesProvider)
        mock_provider.fetch_roles = AsyncMock(return_value=["staff"])
        user = User(id="u4", name="Dave", token="tok", roles_provider=mock_provider)
        await user.roles
        await user.roles
        assert mock_provider.fetch_roles.call_count == 1

    @pytest.mark.asyncio
    async def test_roles_empty_when_provider_but_no_token(self):
        from auth_middleware.providers.authz.roles_provider import RolesProvider
        mock_provider = MagicMock(spec=RolesProvider)
        mock_provider.fetch_roles = AsyncMock(return_value=["admin"])
        user = User(id="u5", name="Eve", roles_provider=mock_provider)
        result = await user.roles
        assert result == []
        mock_provider.fetch_roles.assert_not_called()

