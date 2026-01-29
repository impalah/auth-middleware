"""
Audit Middleware for tracking authentication and authorization events.

This module provides middleware and utilities for logging authentication,
authorization, and security-related events for compliance and monitoring.
"""

import json
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class AuditEvent:
    """Represents an audit event for security logging.

    Attributes:
        timestamp: Event timestamp (UTC)
        event_type: Type of event (auth, authz, access, error)
        user_id: User or service account ID
        client_id: Client ID for M2M tokens
        is_m2m: Whether this is M2M authentication
        path: Request path
        method: HTTP method
        status_code: Response status code
        ip_address: Client IP address
        user_agent: Client user agent
        metadata: Additional event-specific data
    """

    def __init__(
        self,
        event_type: str,
        user_id: str | None = None,
        client_id: str | None = None,
        is_m2m: bool = False,
        path: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        **metadata: Any,
    ):
        """Initialize audit event.

        Args:
            event_type: Event type (auth_success, auth_failure, access_denied, etc.)
            user_id: User or service account identifier
            client_id: Client ID for M2M authentication
            is_m2m: Whether this is M2M authentication
            path: Request path
            method: HTTP method
            status_code: Response status code
            ip_address: Client IP address
            user_agent: User agent string
            **metadata: Additional event-specific data
        """
        self.timestamp = datetime.now(UTC)
        self.event_type = event_type
        self.user_id = user_id
        self.client_id = client_id
        self.is_m2m = is_m2m
        self.path = path
        self.method = method
        self.status_code = status_code
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.metadata = metadata

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary for logging.

        Returns:
            Dictionary representation of event
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "user_id": self.user_id,
            "client_id": self.client_id,
            "is_m2m": self.is_m2m,
            "path": self.path,
            "method": self.method,
            "status_code": self.status_code,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            **self.metadata,
        }

    def to_json(self) -> str:
        """Convert event to JSON string.

        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict())


class AuditLogger:
    """Service for logging security audit events.

    Example:
        ```python
        from auth_middleware.services.audit import AuditLogger, AuditEvent

        audit = AuditLogger()

        # Log successful authentication
        event = AuditEvent(
            event_type="auth_success",
            user_id="user-123",
            path="/api/data",
            method="GET",
            ip_address="192.168.1.1",
        )
        audit.log(event)
        ```
    """

    def __init__(
        self,
        logger_instance: logging.Logger | None = None,
        log_to_console: bool = True,
        log_callback: Callable[[AuditEvent], None] | None = None,
    ):
        """Initialize audit logger.

        Args:
            logger_instance: Custom logger instance (uses default if None)
            log_to_console: Whether to log to console
            log_callback: Optional callback function for custom logging
        """
        self.logger = logger_instance or logger
        self.log_to_console = log_to_console
        self.log_callback = log_callback

    def log(self, event: AuditEvent) -> None:
        """Log an audit event.

        Args:
            event: Audit event to log
        """
        event_dict = event.to_dict()

        # Log to structured logger
        if self.log_to_console:
            self.logger.info(
                f"AUDIT: {event.event_type}",
                extra={"audit_event": event_dict},
            )

        # Call custom callback if provided
        if self.log_callback:
            self.log_callback(event)

    def log_auth_success(
        self,
        user_id: str,
        is_m2m: bool = False,
        client_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Log successful authentication.

        Args:
            user_id: User or service ID
            is_m2m: Whether M2M authentication
            client_id: Client ID for M2M
            **kwargs: Additional event data
        """
        event = AuditEvent(
            event_type="auth_success",
            user_id=user_id,
            is_m2m=is_m2m,
            client_id=client_id,
            **kwargs,
        )
        self.log(event)

    def log_auth_failure(
        self, reason: str, ip_address: str | None = None, **kwargs: Any
    ) -> None:
        """Log failed authentication.

        Args:
            reason: Failure reason
            ip_address: Client IP
            **kwargs: Additional event data
        """
        event = AuditEvent(
            event_type="auth_failure",
            ip_address=ip_address,
            reason=reason,
            **kwargs,
        )
        self.log(event)

    def log_access_denied(
        self,
        user_id: str | None,
        path: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """Log access denial.

        Args:
            user_id: User ID (if authenticated)
            path: Request path
            reason: Denial reason
            **kwargs: Additional event data
        """
        event = AuditEvent(
            event_type="access_denied",
            user_id=user_id,
            path=path,
            reason=reason,
            **kwargs,
        )
        self.log(event)


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware for automatic audit logging of requests.

    Example:
        ```python
        from fastapi import FastAPI
        from auth_middleware.services.audit import AuditMiddleware

        app = FastAPI()

        # Add audit middleware
        app.add_middleware(AuditMiddleware, enabled=True)
        ```
    """

    def __init__(
        self,
        app: ASGIApp,
        enabled: bool = True,
        audit_logger: AuditLogger | None = None,
        exclude_paths: list[str] | None = None,
    ):
        """Initialize audit middleware.

        Args:
            app: ASGI application
            enabled: Whether audit logging is enabled
            audit_logger: Custom audit logger instance
            exclude_paths: Paths to exclude from auditing (e.g., health checks)
        """
        super().__init__(app)
        self.enabled = enabled
        self.audit_logger = audit_logger or AuditLogger()
        self.exclude_paths = exclude_paths or [
            "/health",
            "/metrics",
            "/docs",
            "/openapi.json",
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log audit event.

        Args:
            request: HTTP request
            call_next: Next middleware in chain

        Returns:
            HTTP response
        """
        if not self.enabled:
            return await call_next(request)

        # Skip excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Collect request information
        start_time = time.time()
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        # Extract user info if available
        user_id = None
        client_id = None
        is_m2m = False

        if hasattr(request.state, "current_user"):
            user = request.state.current_user
            user_id = user.id
            is_m2m = getattr(user, "is_m2m", False)
            client_id = getattr(user, "client_id", None)

        # Process request
        try:
            response = await call_next(request)
            status_code = response.status_code

            # Log successful request
            if status_code < 400:
                event = AuditEvent(
                    event_type="request_success",
                    user_id=user_id,
                    client_id=client_id,
                    is_m2m=is_m2m,
                    path=request.url.path,
                    method=request.method,
                    status_code=status_code,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            elif status_code == 401:
                event = AuditEvent(
                    event_type="auth_failure",
                    path=request.url.path,
                    method=request.method,
                    status_code=status_code,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            elif status_code == 403:
                event = AuditEvent(
                    event_type="access_denied",
                    user_id=user_id,
                    path=request.url.path,
                    method=request.method,
                    status_code=status_code,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            else:
                event = AuditEvent(
                    event_type="request_error",
                    user_id=user_id,
                    path=request.url.path,
                    method=request.method,
                    status_code=status_code,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )

            self.audit_logger.log(event)
            return response

        except Exception as exc:
            # Log exception
            event = AuditEvent(
                event_type="request_exception",
                user_id=user_id,
                path=request.url.path,
                method=request.method,
                ip_address=ip_address,
                user_agent=user_agent,
                exception=str(exc),
                exception_type=type(exc).__name__,
            )
            self.audit_logger.log(event)
            raise
