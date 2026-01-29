"""Tests for M2M Token Detector."""

from unittest.mock import MagicMock

import pytest

from auth_middleware.services.m2m_detector import M2MTokenDetector
from auth_middleware.types.jwt import JWTAuthorizationCredentials


class TestM2MTokenDetector:
    """Test suite for M2MTokenDetector."""

    @pytest.fixture
    def user_token(self):
        """Create a mock user authentication token."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "user-12345",
            "cognito:username": "john.doe",
            "email": "john.doe@example.com",
            "given_name": "John",
            "family_name": "Doe",
            "token_use": "id",
            "client_id": "app-client-123",
        }
        return token

    @pytest.fixture
    def m2m_token(self):
        """Create a mock M2M authentication token."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "service-account-123",
            "client_id": "7a8b9c0d1e2f3g4h5i6j",
            "token_use": "access",
            "scope": "api/read api/write",
        }
        return token

    @pytest.fixture
    def m2m_token_minimal(self):
        """Create a minimal M2M token."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "client-credentials-456",
            "client_id": "minimal-client-123",
        }
        return token

    def test_is_m2m_token_with_user_token(self, user_token):
        """Test that user tokens are correctly identified."""
        detector = M2MTokenDetector()
        assert detector.is_m2m_token(user_token) is False

    def test_is_m2m_token_with_m2m_token(self, m2m_token):
        """Test that M2M tokens are correctly identified."""
        detector = M2MTokenDetector()
        assert detector.is_m2m_token(m2m_token) is True

    def test_is_m2m_token_with_minimal_m2m_token(self, m2m_token_minimal):
        """Test M2M detection with minimal token."""
        detector = M2MTokenDetector()
        assert detector.is_m2m_token(m2m_token_minimal) is True

    def test_is_m2m_token_with_username_field(self):
        """Test token with 'username' instead of 'cognito:username'."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "user-789",
            "username": "jane.smith",
            "email": "jane@example.com",
            "token_use": "id",
            "client_id": "app-123",
        }
        detector = M2MTokenDetector()
        assert detector.is_m2m_token(token) is False

    def test_is_m2m_token_access_token_with_user_context(self):
        """Test access token with user context (not M2M)."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "user-999",
            "cognito:username": "user999",
            "email": "user@example.com",
            "token_use": "access",
            "client_id": "app-client-456",
        }
        detector = M2MTokenDetector()
        # Has username and email, so not M2M despite being access token
        assert detector.is_m2m_token(token) is False

    def test_get_client_id_from_m2m_token(self, m2m_token):
        """Test extracting client ID from M2M token."""
        detector = M2MTokenDetector()
        client_id = detector.get_client_id(m2m_token)
        assert client_id == "7a8b9c0d1e2f3g4h5i6j"

    def test_get_client_id_from_user_token(self, user_token):
        """Test extracting client ID from user token."""
        detector = M2MTokenDetector()
        client_id = detector.get_client_id(user_token)
        assert client_id == "app-client-123"

    def test_get_client_id_missing(self):
        """Test token without client_id."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "user-000",
            "cognito:username": "testuser",
        }
        detector = M2MTokenDetector()
        assert detector.get_client_id(token) is None

    def test_get_token_metadata_user_token(self, user_token):
        """Test metadata extraction from user token."""
        detector = M2MTokenDetector()
        metadata = detector.get_token_metadata(user_token)

        assert metadata["is_m2m"] is False
        assert metadata["has_user_context"] is True
        assert metadata["username"] == "john.doe"
        assert metadata["email"] == "john.doe@example.com"
        assert metadata["client_id"] == "app-client-123"
        assert metadata["token_use"] == "id"
        assert metadata["subject"] == "user-12345"

    def test_get_token_metadata_m2m_token(self, m2m_token):
        """Test metadata extraction from M2M token."""
        detector = M2MTokenDetector()
        metadata = detector.get_token_metadata(m2m_token)

        assert metadata["is_m2m"] is True
        assert metadata["has_user_context"] is False
        assert metadata["service_account"] == "7a8b9c0d1e2f3g4h5i6j"
        assert metadata["client_id"] == "7a8b9c0d1e2f3g4h5i6j"
        assert metadata["token_use"] == "access"
        assert metadata["scopes"] == ["api/read", "api/write"]
        assert metadata["subject"] == "service-account-123"

    def test_get_token_metadata_scopes_parsing(self):
        """Test scope string parsing in metadata."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "service-123",
            "client_id": "client-789",
            "scope": "resource.read resource.write resource.delete",
        }
        detector = M2MTokenDetector()
        metadata = detector.get_token_metadata(token)

        assert metadata["scopes"] == [
            "resource.read",
            "resource.write",
            "resource.delete",
        ]

    def test_get_token_metadata_empty_scopes(self):
        """Test token without scopes."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "service-456",
            "client_id": "client-abc",
        }
        detector = M2MTokenDetector()
        metadata = detector.get_token_metadata(token)

        assert metadata["scopes"] == []

    def test_requires_user_context_user_token(self, user_token):
        """Test requires_user_context with user token."""
        detector = M2MTokenDetector()
        assert detector.requires_user_context(user_token) is True

    def test_requires_user_context_m2m_token(self, m2m_token):
        """Test requires_user_context with M2M token."""
        detector = M2MTokenDetector()
        assert detector.requires_user_context(m2m_token) is False

    def test_static_method_usage(self):
        """Test that methods can be used as static methods."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "test-123",
            "client_id": "client-xyz",
        }

        # Should work without instantiating the class
        assert M2MTokenDetector.is_m2m_token(token) is True
        assert M2MTokenDetector.get_client_id(token) == "client-xyz"
        assert M2MTokenDetector.requires_user_context(token) is False

    def test_edge_case_no_token_use(self):
        """Test token without token_use claim."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "service-789",
            "client_id": "no-token-use-client",
        }
        detector = M2MTokenDetector()
        # Should still detect as M2M based on missing username/email
        assert detector.is_m2m_token(token) is True

    def test_edge_case_id_token_without_username(self):
        """Test ID token missing username (unusual/invalid case)."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "anomaly-123",
            "token_use": "id",
            "client_id": "anomaly-client",
        }
        detector = M2MTokenDetector()
        # ID token without username/email is anomalous - likely invalid token
        # We don't classify it as M2M since ID tokens are for users
        assert detector.is_m2m_token(token) is False

    def test_token_with_name_but_no_email(self):
        """Test user token with name but no email."""
        token = MagicMock(spec=JWTAuthorizationCredentials)
        token.claims = {
            "sub": "user-777",
            "cognito:username": "user777",
            "given_name": "Test",
            "token_use": "id",
            "client_id": "app-888",
        }
        detector = M2MTokenDetector()
        # Has username and name, so not M2M
        assert detector.is_m2m_token(token) is False

    def test_comprehensive_m2m_detection(self):
        """Test comprehensive M2M detection scenarios."""
        detector = M2MTokenDetector()

        # Scenario 1: Clear M2M token
        m2m_clear = MagicMock(spec=JWTAuthorizationCredentials)
        m2m_clear.claims = {
            "sub": "service-1",
            "client_id": "service-client",
            "token_use": "access",
        }
        assert detector.is_m2m_token(m2m_clear) is True

        # Scenario 2: Clear user token
        user_clear = MagicMock(spec=JWTAuthorizationCredentials)
        user_clear.claims = {
            "sub": "user-1",
            "cognito:username": "user1",
            "email": "user1@test.com",
            "token_use": "id",
            "client_id": "app-client",
        }
        assert detector.is_m2m_token(user_clear) is False

        # Scenario 3: Borderline - access token with client_id but has email
        borderline = MagicMock(spec=JWTAuthorizationCredentials)
        borderline.claims = {
            "sub": "borderline-1",
            "client_id": "app-client",
            "token_use": "access",
            "email": "borderline@test.com",
        }
        # Has email, so not M2M
        assert detector.is_m2m_token(borderline) is False
