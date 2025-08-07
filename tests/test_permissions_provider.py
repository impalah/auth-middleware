"""
Comprehensive tests for auth_middleware.providers.authz.permissions_provider module.
"""

from unittest.mock import AsyncMock

import pytest

from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
from auth_middleware.types.jwt import JWTAuthorizationCredentials


class TestPermissionsProvider:
    """Test cases for PermissionsProvider abstract class."""

    def test_permissions_provider_is_abstract(self):
        """Test that PermissionsProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            PermissionsProvider()

    def test_permissions_provider_abstract_methods(self):
        """Test that PermissionsProvider has required abstract methods."""
        abstract_methods = PermissionsProvider.__abstractmethods__

        expected_methods = {"fetch_permissions"}

        assert abstract_methods == expected_methods

    def test_permissions_provider_inheritance(self):
        """Test that PermissionsProvider uses ABCMeta metaclass."""
        assert PermissionsProvider.__class__.__name__ == "ABCMeta"

    def test_incomplete_implementation_raises_error(self):
        """Test that incomplete implementations raise TypeError."""

        class IncompleteProvider(PermissionsProvider):
            pass  # Missing fetch_permissions implementation

        with pytest.raises(TypeError):
            IncompleteProvider()

    def test_complete_implementation_can_be_instantiated(self):
        """Test that complete implementation can be instantiated."""

        class CompleteProvider(PermissionsProvider):
            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                return ["permission1", "permission2"]

        provider = CompleteProvider()
        assert isinstance(provider, PermissionsProvider)
        assert isinstance(provider, CompleteProvider)

    @pytest.mark.asyncio
    async def test_complete_implementation_method_works(self):
        """Test that complete implementation method works correctly."""

        class TestProvider(PermissionsProvider):
            def __init__(self):
                self.permissions_data = {
                    "admin": ["read", "write", "delete", "admin"],
                    "manager": ["read", "write", "manage"],
                    "user": ["read", "write"],
                    "viewer": ["read"],
                }

            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                roles = token.claims.get("roles", [])
                if isinstance(roles, str):
                    roles = [roles]

                permissions = set()
                for role in roles:
                    role_permissions = self.permissions_data.get(role, [])
                    permissions.update(role_permissions)

                return sorted(list(permissions))

        provider = TestProvider()

        # Test with admin role
        admin_token = JWTAuthorizationCredentials(
            jwt_token="admin_token",
            header={"alg": "HS256"},
            claims={"sub": "admin_user", "roles": ["admin"]},
            signature="admin_sig",
            message="admin_msg",
        )

        admin_permissions = await provider.fetch_permissions(admin_token)
        assert admin_permissions == ["admin", "delete", "read", "write"]

        # Test with multiple roles
        multi_role_token = JWTAuthorizationCredentials(
            jwt_token="multi_token",
            header={"alg": "HS256"},
            claims={"sub": "multi_user", "roles": ["user", "viewer"]},
            signature="multi_sig",
            message="multi_msg",
        )

        multi_permissions = await provider.fetch_permissions(multi_role_token)
        assert multi_permissions == ["read", "write"]

        # Test with no roles
        no_role_token = JWTAuthorizationCredentials(
            jwt_token="no_role_token",
            header={"alg": "HS256"},
            claims={"sub": "no_role_user"},
            signature="no_role_sig",
            message="no_role_msg",
        )

        no_permissions = await provider.fetch_permissions(no_role_token)
        assert no_permissions == []

    @pytest.mark.asyncio
    async def test_provider_with_error_handling(self):
        """Test provider implementation with proper error handling."""

        class ErrorHandlingProvider(PermissionsProvider):
            def __init__(self):
                self.should_raise = False
                self.error_message = "Permission fetch error"

            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                if self.should_raise:
                    raise RuntimeError(self.error_message)

                user_id = token.claims.get("sub")
                if not user_id:
                    return []

                return [f"permission_{user_id}"]

        provider = ErrorHandlingProvider()

        # Test normal operation
        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "HS256"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        permissions = await provider.fetch_permissions(token)
        assert permissions == ["permission_user123"]

        # Test error condition
        provider.should_raise = True
        with pytest.raises(RuntimeError, match="Permission fetch error"):
            await provider.fetch_permissions(token)

    @pytest.mark.asyncio
    async def test_provider_with_external_database_mock(self):
        """Test provider implementation with external database mocking."""

        class DatabasePermissionsProvider(PermissionsProvider):
            def __init__(self, database):
                self.database = database

            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                user_id = token.claims.get("sub")
                if not user_id:
                    return []

                user_roles = await self.database.get_user_roles(user_id)
                permissions = []
                for role in user_roles:
                    role_permissions = await self.database.get_role_permissions(role)
                    permissions.extend(role_permissions)

                return list(set(permissions))  # Remove duplicates

        # Mock database
        mock_database = AsyncMock()
        mock_database.get_user_roles.return_value = ["role1", "role2"]
        mock_database.get_role_permissions.side_effect = [
            ["read", "write"],  # role1 permissions
            ["write", "delete"],  # role2 permissions
        ]

        provider = DatabasePermissionsProvider(mock_database)

        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "HS256"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        permissions = await provider.fetch_permissions(token)

        # Should contain unique permissions from both roles
        assert set(permissions) == {"read", "write", "delete"}
        mock_database.get_user_roles.assert_called_once_with("user123")
        assert mock_database.get_role_permissions.call_count == 2

    @pytest.mark.asyncio
    async def test_provider_with_caching(self):
        """Test provider implementation with caching behavior."""

        class CachingPermissionsProvider(PermissionsProvider):
            def __init__(self):
                self.cache = {}
                self.call_count = 0

            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                user_id = token.claims.get("sub")
                if not user_id:
                    return []

                if user_id in self.cache:
                    return self.cache[user_id]

                self.call_count += 1
                permissions = [
                    f"cached_permission_{user_id}_1",
                    f"cached_permission_{user_id}_2",
                ]
                self.cache[user_id] = permissions
                return permissions

        provider = CachingPermissionsProvider()

        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "HS256"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        # First call should populate cache
        permissions1 = await provider.fetch_permissions(token)
        assert permissions1 == [
            "cached_permission_user123_1",
            "cached_permission_user123_2",
        ]
        assert provider.call_count == 1

        # Second call should use cache
        permissions2 = await provider.fetch_permissions(token)
        assert permissions2 == permissions1
        assert provider.call_count == 1  # No increment

        # Different user should increment counter
        token2 = JWTAuthorizationCredentials(
            jwt_token="token2",
            header={"alg": "HS256"},
            claims={"sub": "user456"},
            signature="sig2",
            message="msg2",
        )

        permissions3 = await provider.fetch_permissions(token2)
        assert permissions3 == [
            "cached_permission_user456_1",
            "cached_permission_user456_2",
        ]
        assert provider.call_count == 2

    @pytest.mark.asyncio
    async def test_provider_with_scope_based_permissions(self):
        """Test provider implementation with OAuth2 scope-based permissions."""

        class ScopeBasedProvider(PermissionsProvider):
            def __init__(self):
                self.scope_to_permissions = {
                    "read": ["read_users", "read_posts", "read_comments"],
                    "write": ["write_posts", "write_comments"],
                    "admin": ["admin_users", "admin_posts", "admin_comments"],
                    "delete": ["delete_posts", "delete_comments"],
                }

            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                scope = token.claims.get("scope", "")
                scopes = scope.split() if scope else []

                permissions = set()
                for scope_name in scopes:
                    scope_permissions = self.scope_to_permissions.get(scope_name, [])
                    permissions.update(scope_permissions)

                return sorted(list(permissions))

        provider = ScopeBasedProvider()

        # Token with multiple scopes
        multi_scope_token = JWTAuthorizationCredentials(
            jwt_token="multi_scope_token",
            header={"alg": "RS256"},
            claims={"sub": "user123", "scope": "read write admin"},
            signature="multi_scope_sig",
            message="multi_scope_msg",
        )

        permissions = await provider.fetch_permissions(multi_scope_token)
        expected_permissions = sorted(
            [
                "read_users",
                "read_posts",
                "read_comments",  # read scope
                "write_posts",
                "write_comments",  # write scope
                "admin_users",
                "admin_posts",
                "admin_comments",  # admin scope
            ]
        )

        assert permissions == expected_permissions

        # Token with single scope
        single_scope_token = JWTAuthorizationCredentials(
            jwt_token="single_scope_token",
            header={"alg": "RS256"},
            claims={"sub": "user456", "scope": "read"},
            signature="single_scope_sig",
            message="single_scope_msg",
        )

        single_permissions = await provider.fetch_permissions(single_scope_token)
        assert single_permissions == ["read_comments", "read_posts", "read_users"]

        # Token with no scope
        no_scope_token = JWTAuthorizationCredentials(
            jwt_token="no_scope_token",
            header={"alg": "RS256"},
            claims={"sub": "user789"},
            signature="no_scope_sig",
            message="no_scope_msg",
        )

        no_permissions = await provider.fetch_permissions(no_scope_token)
        assert no_permissions == []

    @pytest.mark.asyncio
    async def test_provider_with_hierarchical_permissions(self):
        """Test provider implementation with hierarchical permission system."""

        class HierarchicalProvider(PermissionsProvider):
            def __init__(self):
                self.permission_hierarchy = {
                    "admin": ["admin", "manage", "write", "read"],
                    "manage": ["manage", "write", "read"],
                    "write": ["write", "read"],
                    "read": ["read"],
                }
                self.resource_permissions = {
                    "users": ["admin", "manage", "write", "read"],
                    "posts": ["admin", "manage", "write", "read"],
                    "comments": ["write", "read"],
                }

            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                user_level = token.claims.get("permission_level", "read")
                resources = token.claims.get("resources", [])
                if isinstance(resources, str):
                    resources = [resources]

                permissions = set()
                user_permissions = self.permission_hierarchy.get(user_level, ["read"])

                for resource in resources:
                    resource_allowed = self.resource_permissions.get(resource, [])
                    for perm in user_permissions:
                        if perm in resource_allowed:
                            permissions.add(f"{perm}_{resource}")

                return sorted(list(permissions))

        provider = HierarchicalProvider()

        # Admin user with all resources
        admin_token = JWTAuthorizationCredentials(
            jwt_token="admin_token",
            header={"alg": "RS256"},
            claims={
                "sub": "admin_user",
                "permission_level": "admin",
                "resources": ["users", "posts", "comments"],
            },
            signature="admin_sig",
            message="admin_msg",
        )

        admin_permissions = await provider.fetch_permissions(admin_token)
        expected_admin_permissions = sorted(
            [
                "admin_users",
                "manage_users",
                "write_users",
                "read_users",
                "admin_posts",
                "manage_posts",
                "write_posts",
                "read_posts",
                "write_comments",
                "read_comments",  # comments don't support admin/manage
            ]
        )

        assert admin_permissions == expected_admin_permissions

        # Write user with limited resources
        write_token = JWTAuthorizationCredentials(
            jwt_token="write_token",
            header={"alg": "RS256"},
            claims={
                "sub": "write_user",
                "permission_level": "write",
                "resources": ["posts", "comments"],
            },
            signature="write_sig",
            message="write_msg",
        )

        write_permissions = await provider.fetch_permissions(write_token)
        expected_write_permissions = sorted(
            ["write_posts", "read_posts", "write_comments", "read_comments"]
        )

        assert write_permissions == expected_write_permissions

    @pytest.mark.asyncio
    async def test_provider_with_conditional_permissions(self):
        """Test provider implementation with conditional permission logic."""

        class ConditionalProvider(PermissionsProvider):
            def __init__(self):
                self.base_permissions = ["read_public"]
                self.verified_permissions = ["read_private", "write_public"]
                self.premium_permissions = ["read_premium", "write_premium"]
                self.admin_permissions = ["admin_all"]

            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                permissions = list(self.base_permissions)

                # Check verification status
                is_verified = token.claims.get("email_verified", False)
                if is_verified:
                    permissions.extend(self.verified_permissions)

                # Check premium status
                is_premium = token.claims.get("subscription", "free") == "premium"
                if is_premium:
                    permissions.extend(self.premium_permissions)

                # Check admin status
                is_admin = "admin" in token.claims.get("roles", [])
                if is_admin:
                    permissions.extend(self.admin_permissions)

                # Check time-based permissions
                exp = token.claims.get("exp", 0)
                if exp > 9999999999:  # Far future date
                    permissions.append("long_term_access")

                return sorted(list(set(permissions)))

        provider = ConditionalProvider()

        # Basic unverified user
        basic_token = JWTAuthorizationCredentials(
            jwt_token="basic_token",
            header={"alg": "RS256"},
            claims={
                "sub": "basic_user",
                "email_verified": False,
                "subscription": "free",
                "roles": [],
                "exp": 1234567890,
            },
            signature="basic_sig",
            message="basic_msg",
        )

        basic_permissions = await provider.fetch_permissions(basic_token)
        assert basic_permissions == ["read_public"]

        # Verified premium admin user
        premium_token = JWTAuthorizationCredentials(
            jwt_token="premium_token",
            header={"alg": "RS256"},
            claims={
                "sub": "premium_user",
                "email_verified": True,
                "subscription": "premium",
                "roles": ["admin", "user"],
                "exp": 9999999999 + 1,  # One more than the threshold
            },
            signature="premium_sig",
            message="premium_msg",
        )

        premium_permissions = await provider.fetch_permissions(premium_token)
        expected_premium_permissions = sorted(
            [
                "read_public",
                "read_private",
                "write_public",  # base + verified
                "read_premium",
                "write_premium",  # premium
                "admin_all",  # admin
                "long_term_access",  # time-based
            ]
        )

        assert premium_permissions == expected_premium_permissions

    @pytest.mark.asyncio
    async def test_provider_with_async_context_manager(self):
        """Test provider implementation with async context manager."""

        class ContextManagerProvider(PermissionsProvider):
            def __init__(self):
                self.connection_open = False
                self.permissions_database = {
                    "user123": ["read", "write"],
                    "user456": ["read"],
                }

            async def __aenter__(self):
                self.connection_open = True
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                self.connection_open = False
                return False

            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                if not self.connection_open:
                    raise RuntimeError("Connection not open")

                user_id = token.claims.get("sub")
                return self.permissions_database.get(user_id, [])

        async with ContextManagerProvider() as provider:
            assert provider.connection_open is True

            token = JWTAuthorizationCredentials(
                jwt_token="token",
                header={"alg": "HS256"},
                claims={"sub": "user123"},
                signature="sig",
                message="msg",
            )

            permissions = await provider.fetch_permissions(token)
            assert permissions == ["read", "write"]

        # Connection should be closed after context
        assert provider.connection_open is False

    @pytest.mark.asyncio
    async def test_provider_with_multi_tenant_support(self):
        """Test provider implementation with multi-tenant support."""

        class MultiTenantProvider(PermissionsProvider):
            def __init__(self):
                self.tenant_permissions = {
                    "tenant1": {
                        "admin": ["read", "write", "delete", "admin"],
                        "user": ["read", "write"],
                    },
                    "tenant2": {
                        "admin": ["read", "write", "admin"],  # No delete in tenant2
                        "user": ["read"],  # Limited user permissions in tenant2
                    },
                }

            async def fetch_permissions(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                tenant_id = token.claims.get("tenant_id")
                user_role = token.claims.get("role", "user")

                if not tenant_id:
                    return []

                tenant_config = self.tenant_permissions.get(tenant_id, {})
                permissions = tenant_config.get(user_role, [])

                # Add tenant prefix to permissions
                return [f"{tenant_id}:{perm}" for perm in permissions]

        provider = MultiTenantProvider()

        # Tenant1 admin
        tenant1_admin_token = JWTAuthorizationCredentials(
            jwt_token="tenant1_admin_token",
            header={"alg": "RS256"},
            claims={"sub": "admin_user", "tenant_id": "tenant1", "role": "admin"},
            signature="tenant1_admin_sig",
            message="tenant1_admin_msg",
        )

        tenant1_admin_permissions = await provider.fetch_permissions(
            tenant1_admin_token
        )
        assert tenant1_admin_permissions == [
            "tenant1:read",
            "tenant1:write",
            "tenant1:delete",
            "tenant1:admin",
        ]

        # Tenant2 user (more restricted)
        tenant2_user_token = JWTAuthorizationCredentials(
            jwt_token="tenant2_user_token",
            header={"alg": "RS256"},
            claims={"sub": "user", "tenant_id": "tenant2", "role": "user"},
            signature="tenant2_user_sig",
            message="tenant2_user_msg",
        )

        tenant2_user_permissions = await provider.fetch_permissions(tenant2_user_token)
        assert tenant2_user_permissions == ["tenant2:read"]

        # No tenant (should return empty)
        no_tenant_token = JWTAuthorizationCredentials(
            jwt_token="no_tenant_token",
            header={"alg": "RS256"},
            claims={"sub": "user", "role": "admin"},
            signature="no_tenant_sig",
            message="no_tenant_msg",
        )

        no_tenant_permissions = await provider.fetch_permissions(no_tenant_token)
        assert no_tenant_permissions == []
