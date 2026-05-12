"""Tests for abstract provider/repository base class stubs.

Verifies that NotImplementedError is raised by abstract methods.
"""

import pytest

from auth_middleware.contracts.credentials_repository import CredentialsRepository
from auth_middleware.contracts.groups_provider import GroupsProvider
from auth_middleware.contracts.permissions_provider import PermissionsProvider
from auth_middleware.contracts.roles_provider import RolesProvider

# ---------------------------------------------------------------------------
# Concrete stubs that delegate to super() to execute the base class body
# ---------------------------------------------------------------------------


class ConcreteGroupsProvider(GroupsProvider):
    async def fetch_groups(self, token):
        return await super().fetch_groups(token)


class ConcretePermissionsProvider(PermissionsProvider):
    async def fetch_permissions(self, token):
        return await super().fetch_permissions(token)


class ConcreteRolesProvider(RolesProvider):
    async def fetch_roles(self, token):
        return await super().fetch_roles(token)


class ConcreteCredentialsRepository(CredentialsRepository):
    async def get_by_id(self, *, id):
        return await super().get_by_id(id=id)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAbstractProviderStubs:
    @pytest.mark.asyncio
    async def test_groups_provider_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            await ConcreteGroupsProvider().fetch_groups("token")

    @pytest.mark.asyncio
    async def test_permissions_provider_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            await ConcretePermissionsProvider().fetch_permissions("token")

    @pytest.mark.asyncio
    async def test_roles_provider_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            await ConcreteRolesProvider().fetch_roles("token")

    @pytest.mark.asyncio
    async def test_credentials_repository_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            await ConcreteCredentialsRepository().get_by_id(id="abc")
