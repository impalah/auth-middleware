"""Tests for Audit Logger and Middleware."""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from auth_middleware.services.audit import (
    AuditEvent,
    AuditLogger,
    AuditMiddleware,
)


class TestAuditEvent:
    """Test suite for AuditEvent."""

    def test_event_initialization(self):
        """Test basic event initialization."""
        event = AuditEvent(
            event_type="auth_success",
            user_id="user-123",
            path="/api/data",
            method="GET",
        )

        assert event.event_type == "auth_success"
        assert event.user_id == "user-123"
        assert event.path == "/api/data"
        assert event.method == "GET"
        assert isinstance(event.timestamp, datetime)

    def test_event_with_m2m(self):
        """Test event with M2M authentication."""
        event = AuditEvent(
            event_type="auth_success",
            user_id="service-account-1",
            client_id="client-abc",
            is_m2m=True,
        )

        assert event.is_m2m is True
        assert event.client_id == "client-abc"

    def test_event_with_metadata(self):
        """Test event with additional metadata."""
        event = AuditEvent(
            event_type="access_denied",
            user_id="user-456",
            reason="insufficient_permissions",
            required_groups=["admin"],
        )

        assert event.metadata["reason"] == "insufficient_permissions"
        assert event.metadata["required_groups"] == ["admin"]

    def test_to_dict(self):
        """Test conversion to dictionary."""
        event = AuditEvent(
            event_type="request_success",
            user_id="user-789",
            path="/api/users",
            method="POST",
            status_code=201,
            ip_address="192.168.1.1",
        )

        event_dict = event.to_dict()

        assert event_dict["event_type"] == "request_success"
        assert event_dict["user_id"] == "user-789"
        assert event_dict["path"] == "/api/users"
        assert event_dict["method"] == "POST"
        assert event_dict["status_code"] == 201
        assert event_dict["ip_address"] == "192.168.1.1"
        assert "timestamp" in event_dict

    def test_to_json(self):
        """Test conversion to JSON string."""
        event = AuditEvent(
            event_type="auth_failure",
            ip_address="10.0.0.1",
            reason="invalid_token",
        )

        json_str = event.to_json()
        parsed = json.loads(json_str)

        assert parsed["event_type"] == "auth_failure"
        assert parsed["ip_address"] == "10.0.0.1"
        assert parsed["reason"] == "invalid_token"


class TestAuditLogger:
    """Test suite for AuditLogger."""

    def test_logger_initialization(self):
        """Test audit logger initialization."""
        audit = AuditLogger()

        assert audit.log_to_console is True
        assert audit.log_callback is None

    def test_logger_with_callback(self):
        """Test audit logger with custom callback."""
        callback = MagicMock()
        audit = AuditLogger(log_callback=callback)

        event = AuditEvent(event_type="test_event")
        audit.log(event)

        callback.assert_called_once()
        called_event = callback.call_args[0][0]
        assert called_event.event_type == "test_event"

    def test_log_method(self):
        """Test basic log method."""
        audit = AuditLogger(log_to_console=False)
        callback = MagicMock()
        audit.log_callback = callback

        event = AuditEvent(
            event_type="custom_event",
            user_id="user-999",
        )

        audit.log(event)

        callback.assert_called_once()

    def test_log_auth_success(self):
        """Test logging authentication success."""
        callback = MagicMock()
        audit = AuditLogger(log_to_console=False, log_callback=callback)

        audit.log_auth_success(
            user_id="user-111",
            is_m2m=False,
            path="/api/login",
        )

        callback.assert_called_once()
        event = callback.call_args[0][0]
        assert event.event_type == "auth_success"
        assert event.user_id == "user-111"
        assert event.is_m2m is False

    def test_log_auth_success_m2m(self):
        """Test logging M2M authentication success."""
        callback = MagicMock()
        audit = AuditLogger(log_to_console=False, log_callback=callback)

        audit.log_auth_success(
            user_id="service-account",
            is_m2m=True,
            client_id="client-xyz",
        )

        event = callback.call_args[0][0]
        assert event.is_m2m is True
        assert event.client_id == "client-xyz"

    def test_log_auth_failure(self):
        """Test logging authentication failure."""
        callback = MagicMock()
        audit = AuditLogger(log_to_console=False, log_callback=callback)

        audit.log_auth_failure(
            reason="invalid_credentials",
            ip_address="192.168.1.100",
        )

        event = callback.call_args[0][0]
        assert event.event_type == "auth_failure"
        assert event.metadata["reason"] == "invalid_credentials"
        assert event.ip_address == "192.168.1.100"

    def test_log_access_denied(self):
        """Test logging access denial."""
        callback = MagicMock()
        audit = AuditLogger(log_to_console=False, log_callback=callback)

        audit.log_access_denied(
            user_id="user-222",
            path="/admin/panel",
            reason="insufficient_permissions",
        )

        event = callback.call_args[0][0]
        assert event.event_type == "access_denied"
        assert event.user_id == "user-222"
        assert event.path == "/admin/panel"
        assert event.metadata["reason"] == "insufficient_permissions"

    def test_multiple_events(self):
        """Test logging multiple events."""
        callback = MagicMock()
        audit = AuditLogger(log_to_console=False, log_callback=callback)

        audit.log_auth_success(user_id="user-1")
        audit.log_auth_failure(reason="expired_token")
        audit.log_access_denied(user_id="user-2", path="/protected", reason="no_access")

        assert callback.call_count == 3


class TestAuditMiddleware:
    """Test suite for AuditMiddleware."""

    @pytest.fixture
    def audit_logger(self):
        """Create shared audit logger for tests."""
        callback = MagicMock()
        return AuditLogger(log_to_console=False, log_callback=callback)

    @pytest.fixture
    def app(self, audit_logger):
        """Create test FastAPI app with audit middleware."""
        from starlette.middleware.base import BaseHTTPMiddleware

        app = FastAPI()

        # Add audit middleware first
        app.add_middleware(
            AuditMiddleware,
            enabled=True,
            audit_logger=audit_logger,
        )

        # Mock user middleware (added after, so runs BEFORE audit middleware)
        class MockUserMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next):
                if request.url.path == "/protected":
                    user_mock = MagicMock()
                    user_mock.id = "user-test"
                    user_mock.is_m2m = False
                    user_mock.client_id = None
                    request.state.current_user = user_mock
                return await call_next(request)

        app.add_middleware(MockUserMiddleware)

        @app.get("/test")
        async def test_endpoint():
            return {"status": "ok"}

        @app.get("/protected")
        async def protected_endpoint(request: Request):
            return {"status": "ok"}

        @app.get("/error")
        async def error_endpoint():
            raise ValueError("Test error")

        return app

    def test_middleware_logs_successful_request(self, app, audit_logger):
        """Test middleware logs successful requests."""
        client = TestClient(app)

        with patch.object(audit_logger, "log") as mock_log:
            response = client.get("/test")

            assert response.status_code == 200
            mock_log.assert_called_once()

            event = mock_log.call_args[0][0]
            assert event.event_type == "request_success"
            assert event.path == "/test"
            assert event.method == "GET"
            assert event.status_code == 200

    def test_middleware_excluded_paths(self, app, audit_logger):
        """Test middleware skips excluded paths."""
        client = TestClient(app)

        # Add health endpoint
        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        with patch.object(audit_logger, "log") as mock_log:
            response = client.get("/health")

            assert response.status_code == 200
            # Should not log excluded path
            mock_log.assert_not_called()

    def test_middleware_disabled(self):
        """Test middleware when disabled."""
        app = FastAPI()

        callback = MagicMock()
        audit_logger = AuditLogger(log_to_console=False, log_callback=callback)

        app.add_middleware(
            AuditMiddleware,
            enabled=False,  # Disabled
            audit_logger=audit_logger,
        )

        @app.get("/test")
        async def test_endpoint():
            return {"status": "ok"}

        client = TestClient(app)
        response = client.get("/test")

        assert response.status_code == 200
        # Should not log when disabled
        callback.assert_not_called()

    def test_middleware_with_user_context(self, app, audit_logger):
        """Test middleware with authenticated user."""
        client = TestClient(app)

        with patch.object(audit_logger, "log") as mock_log:
            response = client.get("/protected")

            assert response.status_code == 200
            mock_log.assert_called_once()

            event = mock_log.call_args[0][0]
            assert event.user_id == "user-test"
            assert event.is_m2m is False

    def test_middleware_logs_exception(self, app, audit_logger):
        """Test middleware logs exceptions."""
        client = TestClient(app)

        with patch.object(audit_logger, "log") as mock_log:
            with pytest.raises(ValueError):
                client.get("/error")

            mock_log.assert_called_once()
            event = mock_log.call_args[0][0]
            assert event.event_type == "request_exception"
            assert "Test error" in event.metadata.get("exception", "")

    def test_middleware_includes_duration(self, app, audit_logger):
        """Test middleware includes request duration."""
        client = TestClient(app)

        with patch.object(audit_logger, "log") as mock_log:
            response = client.get("/test")

            assert response.status_code == 200
            event = mock_log.call_args[0][0]
            assert "duration_ms" in event.metadata
            assert event.metadata["duration_ms"] >= 0

    def test_middleware_captures_ip_and_user_agent(self, app, audit_logger):
        """Test middleware captures IP and user agent."""
        client = TestClient(app)

        with patch.object(audit_logger, "log") as mock_log:
            response = client.get(
                "/test",
                headers={"User-Agent": "TestClient/1.0"},
            )

            assert response.status_code == 200
            event = mock_log.call_args[0][0]
            assert event.ip_address is not None
            assert event.user_agent == "TestClient/1.0"
