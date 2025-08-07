"""
Comprehensive tests for auth_middleware.providers.authn.jwt_provider module.
"""

from time import time_ns
from unittest.mock import AsyncMock, Mock, patch

import pytest

from auth_middleware.providers.authn.jwt_provider import JWTProvider
from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings
from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
from auth_middleware.types.jwt import JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User


class TestJWTProvider:
    """Test cases for JWTProvider abstract class."""

    def test_jwt_provider_is_abstract(self):
        """Test that JWTProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            JWTProvider()

    def test_jwt_provider_abstract_methods(self):
        """Test that JWTProvider has required abstract methods."""
        abstract_methods = JWTProvider.__abstractmethods__

        expected_methods = {"load_jwks", "verify_token", "create_user_from_token"}

        assert abstract_methods == expected_methods

    def test_jwt_provider_inheritance(self):
        """Test that JWTProvider uses ABCMeta metaclass."""
        assert JWTProvider.__class__.__name__ == "ABCMeta"

    def test_incomplete_implementation_raises_error(self):
        """Test that incomplete implementations raise TypeError."""

        # Missing load_jwks method
        class IncompleteProvider1(JWTProvider):
            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        # Missing verify_token method
        class IncompleteProvider2(JWTProvider):
            async def load_jwks(self) -> JWKS:
                return JWKS(keys=[])

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        # Missing create_user_from_token method
        class IncompleteProvider3(JWTProvider):
            async def load_jwks(self) -> JWKS:
                return JWKS(keys=[])

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

        # All incomplete providers should raise TypeError
        with pytest.raises(TypeError):
            IncompleteProvider1()

        with pytest.raises(TypeError):
            IncompleteProvider2()

        with pytest.raises(TypeError):
            IncompleteProvider3()

    def test_complete_implementation_can_be_instantiated(self):
        """Test that complete implementation can be instantiated."""

        class CompleteProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                return JWKS(keys=[])

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = CompleteProvider()
        assert isinstance(provider, JWTProvider)
        assert isinstance(provider, CompleteProvider)

    def test_jwt_provider_initialization_with_settings(self):
        """Test JWTProvider initialization with settings and providers."""

        class TestProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                return JWKS(keys=[])

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        # Mock dependencies
        mock_settings = Mock(spec=JWTProviderSettings)
        mock_permissions_provider = Mock(spec=PermissionsProvider)
        mock_groups_provider = Mock(spec=GroupsProvider)

        provider = TestProvider(
            settings=mock_settings,
            permissions_provider=mock_permissions_provider,
            groups_provider=mock_groups_provider,
        )

        assert provider._settings == mock_settings
        assert provider._permissions_provider == mock_permissions_provider
        assert provider._groups_provider == mock_groups_provider

    def test_jwt_provider_initialization_without_settings(self):
        """Test JWTProvider initialization without settings."""

        class TestProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                return JWKS(keys=[])

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = TestProvider()

        assert provider._settings is None
        assert provider._permissions_provider is None
        assert provider._groups_provider is None

    @pytest.mark.asyncio
    async def test_get_jwks_first_time_load(self):
        """Test _get_jwks method on first load (no cache)."""

        class TestProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                return JWKS(keys=[{"kid": "test-key", "kty": "RSA"}])

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = TestProvider()

        # Mock time_ns to control timestamp comparison
        with patch(
            "auth_middleware.providers.authn.jwt_provider.time_ns",
            return_value=1000000000,
        ):
            jwks = await provider._get_jwks()

        assert jwks is not None
        assert len(jwks.keys) == 1
        assert jwks.keys[0]["kid"] == "test-key"
        assert hasattr(provider, "jks")

    @pytest.mark.asyncio
    async def test_get_jwks_cache_hit(self):
        """Test _get_jwks method with valid cache."""

        load_count = 0

        class TestProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                nonlocal load_count
                load_count += 1
                jwks = JWKS(keys=[{"kid": "test-key", "kty": "RSA"}])
                jwks.timestamp = time_ns() + 1000000000  # Future timestamp
                jwks.usage_counter = 5
                return jwks

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = TestProvider()

        # First call should load
        jwks1 = await provider._get_jwks()
        assert load_count == 1
        assert jwks1.usage_counter == 4  # Decremented from 5

        # Second call should use cache
        jwks2 = await provider._get_jwks()
        assert load_count == 1  # No additional load
        assert jwks2.usage_counter == 3  # Decremented again

    @pytest.mark.asyncio
    async def test_get_jwks_cache_expired_by_time(self):
        """Test _get_jwks method with time-expired cache."""

        load_count = 0

        class TestProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                nonlocal load_count
                load_count += 1
                jwks = JWKS(keys=[{"kid": f"test-key-{load_count}", "kty": "RSA"}])
                # Use fixed timestamps instead of time_ns() to avoid patching issues
                if load_count == 1:
                    jwks.timestamp = 1500000000  # Fixed timestamp for first load
                else:
                    jwks.timestamp = 3000000000  # Fixed timestamp for second load
                jwks.usage_counter = 5
                return jwks

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = TestProvider()

        # First load - timestamp will be 1500000000
        with patch(
            "auth_middleware.providers.authn.jwt_provider.time_ns",
            return_value=500000000,
        ):
            jwks1 = await provider._get_jwks()
            assert load_count == 1
            assert jwks1.keys[0]["kid"] == "test-key-1"

        # Simulate time passing, cache should expire (current_time > timestamp)
        with patch(
            "auth_middleware.providers.authn.jwt_provider.time_ns",
            return_value=1500000001,
        ):  # Past the timestamp
            jwks2 = await provider._get_jwks()
            assert load_count == 2  # Should reload
            assert jwks2.keys[0]["kid"] == "test-key-2"

    @pytest.mark.asyncio
    async def test_get_jwks_cache_expired_by_usage(self):
        """Test _get_jwks method with usage-expired cache."""

        load_count = 0

        class TestProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                nonlocal load_count
                load_count += 1
                jwks = JWKS(keys=[{"kid": f"test-key-{load_count}", "kty": "RSA"}])
                jwks.timestamp = time_ns() + 1000000000  # Far future
                jwks.usage_counter = 1  # Only one usage allowed
                return jwks

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = TestProvider()

        # First call uses the cache
        jwks1 = await provider._get_jwks()
        assert load_count == 1
        assert jwks1.usage_counter == 0  # Decremented to 0

        # Second call should reload because usage_counter is 0
        jwks2 = await provider._get_jwks()
        assert load_count == 2  # Should reload
        assert jwks2.keys[0]["kid"] == "test-key-2"

    @pytest.mark.asyncio
    async def test_get_jwks_load_error(self):
        """Test _get_jwks method when load_jwks raises KeyError."""

        class ErrorProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                raise KeyError("JWKS load failed")

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = ErrorProvider()

        jwks = await provider._get_jwks()
        assert jwks is None

    @pytest.mark.asyncio
    async def test_get_hmac_key_found(self):
        """Test _get_hmac_key method when key is found."""

        class TestProvider(JWTProvider):
            def __init__(self):
                super().__init__()
                self.jks = JWKS(
                    keys=[
                        {"kid": "key1", "kty": "RSA", "alg": "RS256"},
                        {"kid": "key2", "kty": "RSA", "alg": "RS256"},
                    ]
                )
                self.jks.timestamp = time_ns() + 1000000000
                self.jks.usage_counter = 5

            async def load_jwks(self) -> JWKS:
                return self.jks

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = TestProvider()

        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "RS256", "kid": "key2"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        key = await provider._get_hmac_key(token)

        assert key is not None
        assert key["kid"] == "key2"
        assert key["kty"] == "RSA"

    @pytest.mark.asyncio
    async def test_get_hmac_key_not_found(self):
        """Test _get_hmac_key method when key is not found."""

        class TestProvider(JWTProvider):
            def __init__(self):
                super().__init__()
                self.jks = JWKS(keys=[{"kid": "key1", "kty": "RSA", "alg": "RS256"}])
                self.jks.timestamp = time_ns() + 1000000000
                self.jks.usage_counter = 5

            async def load_jwks(self) -> JWKS:
                return self.jks

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = TestProvider()

        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "RS256", "kid": "unknown_key"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        key = await provider._get_hmac_key(token)

        assert key is None

    @pytest.mark.asyncio
    async def test_get_hmac_key_no_jwks(self):
        """Test _get_hmac_key method when JWKS is None."""

        class TestProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                raise KeyError("No JWKS available")

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                return User(id="test")

        provider = TestProvider()

        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "RS256", "kid": "key1"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        key = await provider._get_hmac_key(token)

        assert key is None

    @pytest.mark.asyncio
    async def test_complete_implementation_workflow(self):
        """Test complete JWT provider implementation workflow."""

        class WorkflowProvider(JWTProvider):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.jwks_data = JWKS(
                    keys=[
                        {"kid": "rsa-key-1", "kty": "RSA", "alg": "RS256", "use": "sig"}
                    ]
                )
                self.jwks_data.timestamp = time_ns() + 1000000000
                self.jwks_data.usage_counter = 10

            async def load_jwks(self) -> JWKS:
                return self.jwks_data

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                # Simple verification: check if token has required fields
                return all(
                    [
                        token.jwt_token,
                        token.header.get("alg") in ["RS256", "HS256"],
                        token.claims.get("sub"),
                        token.signature,
                    ]
                )

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                user_id = token.claims.get("sub")
                email = token.claims.get("email")
                name = token.claims.get("name", user_id)

                return User(id=user_id, email=email, name=name)

        # Mock providers
        mock_groups_provider = AsyncMock(spec=GroupsProvider)
        mock_groups_provider.fetch_groups.return_value = ["admin", "users"]

        mock_permissions_provider = AsyncMock(spec=PermissionsProvider)
        mock_permissions_provider.fetch_permissions.return_value = [
            "read",
            "write",
            "admin",
        ]

        provider = WorkflowProvider(
            groups_provider=mock_groups_provider,
            permissions_provider=mock_permissions_provider,
        )

        # Test JWKS loading
        jwks = await provider._get_jwks()
        assert jwks is not None
        assert len(jwks.keys) == 1

        # Test key lookup
        token = JWTAuthorizationCredentials(
            jwt_token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS1rZXktMSJ9...",
            header={"alg": "RS256", "typ": "JWT", "kid": "rsa-key-1"},
            claims={
                "sub": "user123",
                "email": "user@example.com",
                "name": "John Doe",
                "iss": "https://auth.example.com",
                "exp": 9999999999,
            },
            signature="signature_value",
            message="header.payload",
        )

        key = await provider._get_hmac_key(token)
        assert key is not None
        assert key["kid"] == "rsa-key-1"

        # Test token verification
        is_valid = await provider.verify_token(token)
        assert is_valid is True

        # Test user creation
        user = await provider.create_user_from_token(token)
        assert user.id == "user123"
        assert user.email == "user@example.com"
        assert user.name == "John Doe"

    @pytest.mark.asyncio
    async def test_provider_with_error_scenarios(self):
        """Test JWT provider with various error scenarios."""

        class ErrorTestProvider(JWTProvider):
            def __init__(self, jwks_error=False, verify_error=False, user_error=False):
                super().__init__()
                self.jwks_error = jwks_error
                self.verify_error = verify_error
                self.user_error = user_error

            async def load_jwks(self) -> JWKS:
                if self.jwks_error:
                    raise RuntimeError("JWKS service unavailable")
                return JWKS(keys=[{"kid": "test-key", "kty": "RSA"}])

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                if self.verify_error:
                    raise ValueError("Token verification failed")
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                if self.user_error:
                    raise KeyError("User data not found")
                return User(id="test")

        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "RS256"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        # Test JWKS error
        jwks_error_provider = ErrorTestProvider(jwks_error=True)
        with pytest.raises(RuntimeError, match="JWKS service unavailable"):
            await jwks_error_provider.load_jwks()

        # Test verification error
        verify_error_provider = ErrorTestProvider(verify_error=True)
        with pytest.raises(ValueError, match="Token verification failed"):
            await verify_error_provider.verify_token(token)

        # Test user creation error
        user_error_provider = ErrorTestProvider(user_error=True)
        with pytest.raises(KeyError, match="User data not found"):
            await user_error_provider.create_user_from_token(token)

    @pytest.mark.asyncio
    async def test_provider_with_dependency_injection(self):
        """Test JWT provider with proper dependency injection."""

        class InjectedProvider(JWTProvider):
            async def load_jwks(self) -> JWKS:
                return JWKS(keys=[{"kid": "test-key", "kty": "RSA"}])

            async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
                return True

            async def create_user_from_token(
                self, token: JWTAuthorizationCredentials
            ) -> User:
                user_id = token.claims.get("sub")
                user = User(id=user_id)

                # Use injected providers to enrich user data
                if self._groups_provider:
                    await self._groups_provider.fetch_groups(token)
                    # In real implementation, you'd set user.groups or similar

                if self._permissions_provider:
                    await self._permissions_provider.fetch_permissions(token)
                    # In real implementation, you'd set user.permissions or similar

                return user

        # Mock providers with specific behavior
        mock_groups_provider = AsyncMock(spec=GroupsProvider)
        mock_groups_provider.fetch_groups.return_value = ["test_group"]

        mock_permissions_provider = AsyncMock(spec=PermissionsProvider)
        mock_permissions_provider.fetch_permissions.return_value = ["test_permission"]

        mock_settings = Mock(spec=JWTProviderSettings)

        provider = InjectedProvider(
            settings=mock_settings,
            groups_provider=mock_groups_provider,
            permissions_provider=mock_permissions_provider,
        )

        token = JWTAuthorizationCredentials(
            jwt_token="token",
            header={"alg": "RS256"},
            claims={"sub": "user123"},
            signature="sig",
            message="msg",
        )

        user = await provider.create_user_from_token(token)

        # Verify dependencies were called
        mock_groups_provider.fetch_groups.assert_called_once_with(token)
        mock_permissions_provider.fetch_permissions.assert_called_once_with(token)

        assert user.id == "user123"
