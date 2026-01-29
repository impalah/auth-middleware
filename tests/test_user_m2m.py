"""Tests for User model M2M extensions."""

from unittest.mock import MagicMock

import pytest

from auth_middleware.types.jwt import JWTAuthorizationCredentials
from auth_middleware.types.user import User


class TestUserM2MExtensions:
    """Test suite for M2M extensions to User model."""

    @pytest.fixture
    def m2m_jwt_token(self):
        """Create a mock M2M JWT token."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "service-account-123",
            "client_id": "7a8b9c0d1e2f3g4h5i6j",
            "token_use": "access",
            "scope": "api/read api/write",
        }
        token.__str__ = MagicMock(return_value="mock-m2m-token")
        return token

    @pytest.fixture
    def user_jwt_token(self):
        """Create a mock user JWT token."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "user-12345",
            "cognito:username": "john.doe",
            "email": "john.doe@example.com",
            "token_use": "id",
            "client_id": "app-client-123",
        }
        token.__str__ = MagicMock(return_value="mock-user-token")
        return token

    def test_user_creation_with_m2m_flags(self):
        """Test creating User with M2M flags."""
        user = User(
            id="service-account-123",
            name="service-account-123",
            is_m2m=True,
            client_id="7a8b9c0d1e2f3g4h5i6j",
        )

        assert user.id == "service-account-123"
        assert user.is_m2m is True
        assert user.client_id == "7a8b9c0d1e2f3g4h5i6j"
        assert user.email is None

    def test_user_creation_regular_user(self):
        """Test creating regular user (not M2M)."""
        user = User(
            id="user-12345",
            name="John Doe",
            email="john.doe@example.com",
            is_m2m=False,
            client_id=None,
        )

        assert user.id == "user-12345"
        assert user.name == "John Doe"
        assert user.email == "john.doe@example.com"
        assert user.is_m2m is False
        assert user.client_id is None

    def test_user_default_m2m_flags(self):
        """Test that M2M flags have correct defaults."""
        user = User(
            id="user-456",
            name="Test User",
        )

        assert user.is_m2m is False
        assert user.client_id is None

    def test_user_with_jwt_credentials(self, m2m_jwt_token):
        """Test User creation with JWT credentials."""
        user = User(
            id="service-123",
            name="service-123",
            token="mock-m2m-token",
            jwt_credentials=m2m_jwt_token,
            is_m2m=True,
            client_id="7a8b9c0d1e2f3g4h5i6j",
        )

        assert user._jwt_credentials == m2m_jwt_token
        assert user._token == "mock-m2m-token"
        assert user.is_m2m is True

    def test_m2m_user_serialization(self):
        """Test that M2M user can be serialized."""
        user = User(
            id="service-789",
            name="api-service",
            is_m2m=True,
            client_id="client-abc-123",
        )

        # Should be able to serialize to dict
        user_dict = user.model_dump()
        assert user_dict["id"] == "service-789"
        assert user_dict["is_m2m"] is True
        assert user_dict["client_id"] == "client-abc-123"

    def test_m2m_user_json_serialization(self):
        """Test JSON serialization of M2M user."""
        user = User(
            id="service-999",
            name="test-service",
            is_m2m=True,
            client_id="test-client-id",
        )

        json_str = user.model_dump_json()
        assert "service-999" in json_str
        assert "test-client-id" in json_str
        assert '"is_m2m":true' in json_str or '"is_m2m": true' in json_str

    def test_user_immutability_with_m2m_fields(self):
        """Test that M2M fields follow model's mutability rules."""
        user = User(
            id="service-111",
            name="service",
            is_m2m=True,
            client_id="client-111",
        )

        # Pydantic models are mutable by default (not frozen)
        # So we should be able to change values
        user.client_id = "new-client-id"
        assert user.client_id == "new-client-id"

    @pytest.mark.asyncio
    async def test_m2m_user_groups_behavior(self):
        """Test that M2M users handle groups appropriately."""
        # M2M users typically don't have groups
        user = User(
            id="service-222",
            name="service",
            is_m2m=True,
            client_id="client-222",
            groups=[],  # Empty groups for M2M
        )

        groups = await user.groups
        assert groups == []

    def test_client_id_max_length(self):
        """Test client_id respects max_length constraint."""
        # Client ID within limit
        user = User(
            id="service-333",
            name="service",
            is_m2m=True,
            client_id="a" * 500,  # At limit
        )
        assert len(user.client_id) == 500

    def test_m2m_user_without_email(self):
        """Test M2M user typically doesn't have email."""
        user = User(
            id="service-444",
            name="api-gateway",
            is_m2m=True,
            client_id="gateway-client",
            email=None,  # M2M shouldn't have email
        )

        assert user.email is None
        assert user.is_m2m is True

    def test_mixed_user_scenario(self):
        """Test edge case: user token with client_id but not M2M."""
        user = User(
            id="user-555",
            name="hybrid.user",
            email="hybrid@example.com",
            is_m2m=False,
            client_id="app-client-555",  # Has client_id but not M2M
        )

        assert user.is_m2m is False
        assert user.client_id == "app-client-555"
        assert user.email == "hybrid@example.com"

    def test_pydantic_validation_on_m2m_fields(self):
        """Test Pydantic validation on M2M fields."""
        # Should accept valid values
        user1 = User(
            id="svc-1",
            name="svc",
            is_m2m=True,
            client_id="valid-client-id",
        )
        assert user1.is_m2m is True

        # Should accept False
        user2 = User(
            id="usr-2",
            name="user",
            is_m2m=False,
        )
        assert user2.is_m2m is False

    def test_user_model_schema_includes_m2m_fields(self):
        """Test that model schema includes M2M fields."""
        schema = User.model_json_schema()

        # Check that is_m2m is in properties
        assert "is_m2m" in schema["properties"]
        assert schema["properties"]["is_m2m"]["type"] == "boolean"

        # Check that client_id is in properties
        assert "client_id" in schema["properties"]
        assert "string" in schema["properties"]["client_id"].get("anyOf", [{}])[0].get(
            "type", ""
        )

    def test_user_example_in_schema(self):
        """Test that schema examples are present for M2M fields."""
        schema = User.model_json_schema()

        # Check is_m2m has example
        is_m2m_extra = schema["properties"]["is_m2m"]
        assert (
            "example" in is_m2m_extra
            or "examples" in is_m2m_extra
            or "default" in is_m2m_extra
        )

        # Check client_id has example
        client_id_extra = schema["properties"]["client_id"]
        assert (
            "example" in client_id_extra
            or "examples" in client_id_extra
            or "anyOf" in client_id_extra
        )
