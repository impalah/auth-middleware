"""
Rate Limiting Service for API endpoints.

This module provides rate limiting functionality using a sliding window
counter algorithm with in-memory storage.
"""

import logging
import time
from collections import defaultdict
from collections.abc import Callable
from functools import wraps

from fastapi import HTTPException, Request
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

logger = logging.getLogger(__name__)


class RateLimiter:
    """In-memory rate limiter using sliding window counter algorithm.

    This rate limiter tracks requests per identifier (e.g., user ID, IP address)
    and enforces configurable rate limits.

    Attributes:
        max_requests: Maximum number of requests allowed in the time window
        window_seconds: Time window in seconds
        _requests: Dict tracking request timestamps per identifier

    Example:
        ```python
        from auth_middleware.services.rate_limiter import RateLimiter

        # Create rate limiter: 100 requests per minute
        limiter = RateLimiter(max_requests=100, window_seconds=60)

        # Check if request is allowed
        if not limiter.is_allowed(user_id="user-123"):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        ```
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        """Initialize rate limiter.

        Args:
            max_requests: Maximum requests allowed in time window
            window_seconds: Time window in seconds (default: 60)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

        logger.debug(
            f"RateLimiter initialized: {max_requests} requests per {window_seconds}s"
        )

    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed for identifier.

        Args:
            identifier: Unique identifier (user ID, IP, client ID, etc.)

        Returns:
            True if request is allowed, False if rate limit exceeded

        Example:
            ```python
            if limiter.is_allowed("user-123"):
                # Process request
                pass
            else:
                # Reject request
                raise HTTPException(status_code=429)
            ```
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Clean up old entries
        self._requests[identifier] = [
            timestamp for timestamp in self._requests[identifier] if timestamp > cutoff
        ]

        # Check if under limit
        if len(self._requests[identifier]) < self.max_requests:
            self._requests[identifier].append(now)
            logger.debug(
                f"Request allowed for {identifier}: "
                f"{len(self._requests[identifier])}/{self.max_requests}"
            )
            return True

        logger.warning(
            f"Rate limit exceeded for {identifier}: "
            f"{len(self._requests[identifier])}/{self.max_requests}"
        )
        return False

    def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for identifier.

        Args:
            identifier: Unique identifier

        Returns:
            Number of requests remaining in current window

        Example:
            ```python
            remaining = limiter.get_remaining("user-123")
            print(f"Requests remaining: {remaining}")
            ```
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Clean up old entries
        self._requests[identifier] = [
            timestamp for timestamp in self._requests[identifier] if timestamp > cutoff
        ]

        current = len(self._requests[identifier])
        remaining = max(0, self.max_requests - current)

        return remaining

    def reset(self, identifier: str) -> None:
        """Reset rate limit for identifier.

        Args:
            identifier: Unique identifier to reset

        Example:
            ```python
            # Reset rate limit for user
            limiter.reset("user-123")
            ```
        """
        if identifier in self._requests:
            del self._requests[identifier]
            logger.debug(f"Rate limit reset for {identifier}")

    def clear_all(self) -> None:
        """Clear all rate limit data.

        Example:
            ```python
            # Clear all rate limits (e.g., for testing)
            limiter.clear_all()
            ```
        """
        self._requests.clear()
        logger.debug("All rate limit data cleared")


def rate_limit(
    max_requests: int = 100,
    window_seconds: int = 60,
    identifier_fn: Callable[[Request], str] | None = None,
) -> Callable:
    """Decorator to apply rate limiting to FastAPI endpoints.

    Args:
        max_requests: Maximum requests allowed in time window
        window_seconds: Time window in seconds
        identifier_fn: Function to extract identifier from request.
                      Defaults to using request.state.current_user.id

    Returns:
        Decorator function

    Example:
        ```python
        from fastapi import APIRouter, Depends, Request
        from auth_middleware.services.rate_limiter import rate_limit

        router = APIRouter()

        @router.get("/api/data")
        @rate_limit(max_requests=10, window_seconds=60)
        async def get_data(request: Request):
            return {"data": "..."}

        # Custom identifier (by IP)
        def get_ip(request: Request) -> str:
            return request.client.host

        @router.post("/api/public")
        @rate_limit(max_requests=5, window_seconds=60, identifier_fn=get_ip)
        async def public_endpoint(request: Request):
            return {"status": "ok"}
        ```
    """
    limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(request: Request, *args, **kwargs):
            # Get identifier
            if identifier_fn:
                identifier = identifier_fn(request)
            elif hasattr(request.state, "current_user"):
                identifier = request.state.current_user.id
            else:
                # Fallback to client IP if no user
                identifier = request.client.host if request.client else "unknown"

            # Check rate limit
            if not limiter.is_allowed(identifier):
                remaining = limiter.get_remaining(identifier)
                raise HTTPException(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Max {max_requests} requests per {window_seconds}s",
                    headers={
                        "X-RateLimit-Limit": str(max_requests),
                        "X-RateLimit-Remaining": str(remaining),
                        "X-RateLimit-Reset": str(int(time.time() + window_seconds)),
                    },
                )

            # Add rate limit headers to response
            response = await func(request, *args, **kwargs)

            # Try to add headers if response supports it
            if hasattr(response, "headers"):
                remaining = limiter.get_remaining(identifier)
                response.headers["X-RateLimit-Limit"] = str(max_requests)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                response.headers["X-RateLimit-Reset"] = str(
                    int(time.time() + window_seconds)
                )

            return response

        @wraps(func)
        def sync_wrapper(request: Request, *args, **kwargs):
            # Get identifier
            if identifier_fn:
                identifier = identifier_fn(request)
            elif hasattr(request.state, "current_user"):
                identifier = request.state.current_user.id
            else:
                identifier = request.client.host if request.client else "unknown"

            # Check rate limit
            if not limiter.is_allowed(identifier):
                remaining = limiter.get_remaining(identifier)
                raise HTTPException(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Max {max_requests} requests per {window_seconds}s",
                    headers={
                        "X-RateLimit-Limit": str(max_requests),
                        "X-RateLimit-Remaining": str(remaining),
                        "X-RateLimit-Reset": str(int(time.time() + window_seconds)),
                    },
                )

            # Execute function
            response = func(request, *args, **kwargs)

            # Try to add headers if response supports it
            if hasattr(response, "headers"):
                remaining = limiter.get_remaining(identifier)
                response.headers["X-RateLimit-Limit"] = str(max_requests)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                response.headers["X-RateLimit-Reset"] = str(
                    int(time.time() + window_seconds)
                )

            return response

        # Return appropriate wrapper based on function type
        import inspect

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator
