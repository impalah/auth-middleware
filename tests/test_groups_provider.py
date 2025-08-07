"""
Comprehensive tests for auth_middleware.providers.authz.groups_provider module.
"""

from unittest.mock import AsyncMock

import pytest

from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.types.jwt import JWTAuthorizationCredentials


class TestGroupsProvider:
    """Test cases for GroupsProvider abstract class."""

    def test_groups_provider_is_abstract(self):
        """Test that GroupsProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            GroupsProvider()

    def test_groups_provider_abstract_methods(self):
        """Test that GroupsProvider has required abstract methods."""
        abstract_methods = GroupsProvider.__abstractmethods__

        expected_methods = {"fetch_groups"}

        assert abstract_methods == expected_methods

    def test_groups_provider_inheritance(self):
        """Test that GroupsProvider uses ABCMeta metaclass."""
        assert GroupsProvider.__class__.__name__ == "ABCMeta"

    def test_incomplete_implementation_raises_error(self):
        """Test that incomplete implementations raise TypeError."""

        class IncompleteProvider(GroupsProvider):
            pass  # Missing fetch_groups implementation

        with pytest.raises(TypeError):
            IncompleteProvider()

    def test_complete_implementation_can_be_instantiated(self):
        """Test that complete implementation can be instantiated."""

        class CompleteProvider(GroupsProvider):
            async def fetch_groups(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                return ["group1", "group2"]

        provider = CompleteProvider()
        assert isinstance(provider, GroupsProvider)
        assert isinstance(provider, CompleteProvider)

    @pytest.mark.asyncio
    async def test_complete_implementation_method_works(self):
        """Test that complete implementation method works correctly."""

        class TestProvider(GroupsProvider):
            def __init__(self):
                self.groups_data = {
                    "user1": ["admin", "users"],
                    "user2": ["users"],
                    "user3": [],
                }

            async def fetch_groups(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                user_id = token.claims.get("sub", "unknown")
                return self.groups_data.get(user_id, [])

        provider = TestProvider()

        # Test with different tokens
        token1 = JWTAuthorizationCredentials(
            jwt_token="token1",
            header={"alg": "HS256"},
            claims={"sub": "user1"},
            signature="sig1",
            message="msg1",
        )

        groups1 = await provider.fetch_groups(token1)
        assert groups1 == ["admin", "users"]

        token2 = JWTAuthorizationCredentials(
            jwt_token="token2",
            header={"alg": "HS256"},
            claims={"sub": "user2"},
            signature="sig2",
            message="msg2",
        )

        groups2 = await provider.fetch_groups(token2)
        assert groups2 == ["users"]

        token_unknown = JWTAuthorizationCredentials(
            jwt_token="token_unknown",
            header={"alg": "HS256"},
            claims={"sub": "unknown_user"},
            signature="sig_unknown",
            message="msg_unknown",
        )

        groups_unknown = await provider.fetch_groups(token_unknown)
        assert groups_unknown == []

    @pytest.mark.asyncio
    async def test_provider_with_error_handling(self):
        """Test provider implementation with proper error handling."""

        class ErrorHandlingProvider(GroupsProvider):
            def __init__(self):
                self.should_raise = False
                self.error_message = "Test error"

            async def fetch_groups(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                if self.should_raise:
                    raise ValueError(self.error_message)

                user_id = token.claims.get("sub")
                if not user_id:
                    return []

                return [f"group_{user_id}"]

        provider = ErrorHandlingProvider()

        # Test normal operation
        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "HS256"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        groups = await provider.fetch_groups(token)
        assert groups == ["group_user123"]

        # Test error condition
        provider.should_raise = True
        with pytest.raises(ValueError, match="Test error"):
            await provider.fetch_groups(token)

    @pytest.mark.asyncio
    async def test_provider_with_external_service_mock(self):
        """Test provider implementation with external service mocking."""

        class ExternalServiceProvider(GroupsProvider):
            def __init__(self, external_service):
                self.external_service = external_service

            async def fetch_groups(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                user_id = token.claims.get("sub")
                if not user_id:
                    return []

                return await self.external_service.get_user_groups(user_id)

        # Mock external service
        mock_service = AsyncMock()
        mock_service.get_user_groups.return_value = [
            "external_group1",
            "external_group2",
        ]

        provider = ExternalServiceProvider(mock_service)

        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "HS256"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        groups = await provider.fetch_groups(token)

        assert groups == ["external_group1", "external_group2"]
        mock_service.get_user_groups.assert_called_once_with("user123")

    @pytest.mark.asyncio
    async def test_provider_with_caching(self):
        """Test provider implementation with caching behavior."""

        class CachingProvider(GroupsProvider):
            def __init__(self):
                self.cache = {}
                self.call_count = 0

            async def fetch_groups(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                user_id = token.claims.get("sub")
                if not user_id:
                    return []

                if user_id in self.cache:
                    return self.cache[user_id]

                self.call_count += 1
                groups = [f"cached_group_{user_id}_1", f"cached_group_{user_id}_2"]
                self.cache[user_id] = groups
                return groups

        provider = CachingProvider()

        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "HS256"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        # First call should populate cache
        groups1 = await provider.fetch_groups(token)
        assert groups1 == ["cached_group_user123_1", "cached_group_user123_2"]
        assert provider.call_count == 1

        # Second call should use cache
        groups2 = await provider.fetch_groups(token)
        assert groups2 == groups1
        assert provider.call_count == 1  # No increment

        # Different user should increment counter
        token2 = JWTAuthorizationCredentials(
            jwt_token="token2",
            header={"alg": "HS256"},
            claims={"sub": "user456"},
            signature="sig2",
            message="msg2",
        )

        groups3 = await provider.fetch_groups(token2)
        assert groups3 == ["cached_group_user456_1", "cached_group_user456_2"]
        assert provider.call_count == 2

    @pytest.mark.asyncio
    async def test_provider_with_token_validation(self):
        """Test provider implementation with token validation."""

        class ValidatingProvider(GroupsProvider):
            def __init__(self):
                self.valid_issuers = {"https://issuer1.com", "https://issuer2.com"}
                self.valid_audiences = {"api.example.com", "app.example.com"}

            async def fetch_groups(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                # Validate issuer
                issuer = token.claims.get("iss")
                if issuer not in self.valid_issuers:
                    raise ValueError(f"Invalid issuer: {issuer}")

                # Validate audience
                audience = token.claims.get("aud")
                if audience not in self.valid_audiences:
                    raise ValueError(f"Invalid audience: {audience}")

                # Validate expiration
                exp = token.claims.get("exp", 0)
                if exp < 1234567890:  # Mock current time
                    raise ValueError("Token expired")

                user_id = token.claims.get("sub")
                return [f"validated_group_{user_id}"]

        provider = ValidatingProvider()

        # Valid token
        valid_token = JWTAuthorizationCredentials(
            jwt_token="valid_token",
            header={"alg": "RS256"},
            claims={
                "sub": "user123",
                "iss": "https://issuer1.com",
                "aud": "api.example.com",
                "exp": 9999999999,
            },
            signature="valid_sig",
            message="valid_msg",
        )

        groups = await provider.fetch_groups(valid_token)
        assert groups == ["validated_group_user123"]

        # Invalid issuer
        invalid_issuer_token = JWTAuthorizationCredentials(
            jwt_token="invalid_token",
            header={"alg": "RS256"},
            claims={
                "sub": "user123",
                "iss": "https://malicious.com",
                "aud": "api.example.com",
                "exp": 9999999999,
            },
            signature="invalid_sig",
            message="invalid_msg",
        )

        with pytest.raises(ValueError, match="Invalid issuer"):
            await provider.fetch_groups(invalid_issuer_token)

        # Invalid audience
        invalid_audience_token = JWTAuthorizationCredentials(
            jwt_token="invalid_token",
            header={"alg": "RS256"},
            claims={
                "sub": "user123",
                "iss": "https://issuer1.com",
                "aud": "malicious.example.com",
                "exp": 9999999999,
            },
            signature="invalid_sig",
            message="invalid_msg",
        )

        with pytest.raises(ValueError, match="Invalid audience"):
            await provider.fetch_groups(invalid_audience_token)

        # Expired token
        expired_token = JWTAuthorizationCredentials(
            jwt_token="expired_token",
            header={"alg": "RS256"},
            claims={
                "sub": "user123",
                "iss": "https://issuer1.com",
                "aud": "api.example.com",
                "exp": 1000000000,  # Past expiration
            },
            signature="expired_sig",
            message="expired_msg",
        )

        with pytest.raises(ValueError, match="Token expired"):
            await provider.fetch_groups(expired_token)

    @pytest.mark.asyncio
    async def test_provider_with_different_token_types(self):
        """Test provider implementation with different token types."""

        class MultiTokenProvider(GroupsProvider):
            async def fetch_groups(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                token_type = token.claims.get("token_use", "access")
                user_id = token.claims.get("sub", "unknown")

                if token_type == "access":
                    return [f"access_group_{user_id}"]
                elif token_type == "id":
                    return [f"id_group_{user_id}"]
                elif token_type == "refresh":
                    return []  # Refresh tokens don't have groups
                else:
                    raise ValueError(f"Unsupported token type: {token_type}")

        provider = MultiTokenProvider()

        # Access token
        access_token = JWTAuthorizationCredentials(
            jwt_token="access_token",
            header={"alg": "RS256"},
            claims={"sub": "user123", "token_use": "access"},
            signature="access_sig",
            message="access_msg",
        )

        access_groups = await provider.fetch_groups(access_token)
        assert access_groups == ["access_group_user123"]

        # ID token
        id_token = JWTAuthorizationCredentials(
            jwt_token="id_token",
            header={"alg": "RS256"},
            claims={"sub": "user123", "token_use": "id"},
            signature="id_sig",
            message="id_msg",
        )

        id_groups = await provider.fetch_groups(id_token)
        assert id_groups == ["id_group_user123"]

        # Refresh token
        refresh_token = JWTAuthorizationCredentials(
            jwt_token="refresh_token",
            header={"alg": "RS256"},
            claims={"sub": "user123", "token_use": "refresh"},
            signature="refresh_sig",
            message="refresh_msg",
        )

        refresh_groups = await provider.fetch_groups(refresh_token)
        assert refresh_groups == []

        # Unsupported token type
        invalid_token = JWTAuthorizationCredentials(
            jwt_token="invalid_token",
            header={"alg": "RS256"},
            claims={"sub": "user123", "token_use": "unsupported"},
            signature="invalid_sig",
            message="invalid_msg",
        )

        with pytest.raises(ValueError, match="Unsupported token type"):
            await provider.fetch_groups(invalid_token)

    @pytest.mark.asyncio
    async def test_provider_with_complex_group_mapping(self):
        """Test provider implementation with complex group mapping logic."""

        class ComplexMappingProvider(GroupsProvider):
            def __init__(self):
                self.role_to_groups = {
                    "admin": ["administrators", "users", "viewers"],
                    "manager": ["managers", "users", "viewers"],
                    "user": ["users", "viewers"],
                    "viewer": ["viewers"],
                }
                self.department_groups = {
                    "engineering": ["eng_team"],
                    "sales": ["sales_team"],
                    "marketing": ["marketing_team"],
                }

            async def fetch_groups(
                self, token: JWTAuthorizationCredentials
            ) -> list[str]:
                groups = set()

                # Add role-based groups
                roles = token.claims.get("roles", [])
                if isinstance(roles, str):
                    roles = [roles]

                for role in roles:
                    role_groups = self.role_to_groups.get(role, [])
                    groups.update(role_groups)

                # Add department-based groups
                department = token.claims.get("department")
                if department:
                    dept_groups = self.department_groups.get(department, [])
                    groups.update(dept_groups)

                # Add custom groups from token
                custom_groups = token.claims.get("groups", [])
                if isinstance(custom_groups, str):
                    custom_groups = [custom_groups]
                groups.update(custom_groups)

                return sorted(list(groups))

        provider = ComplexMappingProvider()

        # Token with multiple roles and department
        complex_token = JWTAuthorizationCredentials(
            jwt_token="complex_token",
            header={"alg": "RS256"},
            claims={
                "sub": "user123",
                "roles": ["admin", "manager"],
                "department": "engineering",
                "groups": ["custom_group1", "custom_group2"],
            },
            signature="complex_sig",
            message="complex_msg",
        )

        groups = await provider.fetch_groups(complex_token)
        expected_groups = sorted(
            [
                "administrators",
                "users",
                "viewers",  # from admin role
                "managers",  # from manager role (users, viewers already included)
                "eng_team",  # from engineering department
                "custom_group1",
                "custom_group2",  # custom groups
            ]
        )

        assert groups == expected_groups

        # Token with single role as string
        simple_token = JWTAuthorizationCredentials(
            jwt_token="simple_token",
            header={"alg": "RS256"},
            claims={"sub": "user456", "roles": "user", "department": "sales"},
            signature="simple_sig",
            message="simple_msg",
        )

        simple_groups = await provider.fetch_groups(simple_token)
        expected_simple_groups = sorted(["users", "viewers", "sales_team"])

        assert simple_groups == expected_simple_groups
