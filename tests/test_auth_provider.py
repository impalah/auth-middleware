import pytest
from abc import ABC

from auth_middleware.auth_provider import AuthProvider
from auth_middleware.types.user import User


class TestAuthProvider:
    """Test the AuthProvider abstract base class."""

    def test_auth_provider_is_abstract(self):
        """Test that AuthProvider cannot be instantiated directly."""
        with pytest.raises(TypeError):
            AuthProvider()

    def test_auth_provider_inheritance(self):
        """Test that AuthProvider can be inherited and implemented."""
        
        class ConcreteAuthProvider(AuthProvider):
            async def validate_credentials(self, credentials):
                return User(id="test_user", name="Test User")
            
            def create_user_from_credentials(self, credentials):
                return User(id="test_user", name="Test User")
        
        # Should be able to instantiate the concrete implementation
        provider = ConcreteAuthProvider()
        assert isinstance(provider, AuthProvider)

    def test_auth_provider_requires_implementation(self):
        """Test that AuthProvider subclasses must implement abstract methods."""
        
        class IncompleteAuthProvider(AuthProvider):
            # Missing implementation of abstract methods
            pass
        
        with pytest.raises(TypeError):
            IncompleteAuthProvider()

    @pytest.mark.asyncio
    async def test_auth_provider_concrete_implementation(self):
        """Test a concrete implementation of AuthProvider."""
        
        class TestAuthProvider(AuthProvider):
            async def validate_credentials(self, credentials):
                if credentials == "valid":
                    return User(id="test_user", name="Test User")
                raise ValueError("Invalid credentials")
            
            def create_user_from_credentials(self, credentials):
                return User(id=credentials, name=f"User {credentials}")
        
        provider = TestAuthProvider()
        
        # Test validate_credentials
        user = await provider.validate_credentials("valid")
        assert user.id == "test_user"
        assert user.name == "Test User"
        
        # Test create_user_from_credentials
        user = provider.create_user_from_credentials("123")
        assert user.id == "123"
        assert user.name == "User 123"
        
        # Test validation failure
        with pytest.raises(ValueError):
            await provider.validate_credentials("invalid")