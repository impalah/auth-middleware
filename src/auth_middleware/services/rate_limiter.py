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
from typing import Any

from fastapi import HTTPException, Request
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

logger = logging.getLogger(__name__)


#: Above this many tracked identifiers, expired ones are swept on the next request.
_SWEEP_THRESHOLD = 10_000


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

        if len(self._requests) > _SWEEP_THRESHOLD:
            self._sweep(cutoff)

        # Clean up old entries
        recent = [t for t in self._requests.get(identifier, ()) if t > cutoff]

        # Check if under limit
        if len(recent) < self.max_requests:
            recent.append(now)
            self._requests[identifier] = recent
            logger.debug(
                "Request allowed for %s: %d/%d",
                identifier,
                len(recent),
                self.max_requests,
            )
            return True

        self._requests[identifier] = recent
        logger.warning(
            "Rate limit exceeded for %s: %d/%d",
            identifier,
            len(recent),
            self.max_requests,
        )
        return False

    def _sweep(self, cutoff: float) -> None:
        """Drop identifiers with no request inside the window (bounds memory)."""
        for key in [
            k
            for k, stamps in self._requests.items()
            if not stamps or stamps[-1] <= cutoff
        ]:
            del self._requests[key]

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

        # Clean up old entries; never create (or keep) an empty key: identifiers can be
        # attacker-chosen, so empty lists would grow the dict without bound.
        recent = [t for t in self._requests.get(identifier, ()) if t > cutoff]
        if recent:
            self._requests[identifier] = recent
        else:
            self._requests.pop(identifier, None)

        return max(0, self.max_requests - len(recent))

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
            logger.debug("Rate limit reset for %s", identifier)

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


def _resolve_identifier(
    request: Request, identifier_fn: Callable[[Request], str] | None
) -> str:
    """Extract a rate-limit identifier from the request."""
    if identifier_fn:
        return identifier_fn(request)
    # current_user is None for anonymous requests: fall back to the client address.
    user = getattr(request.state, "current_user", None)
    if user is not None:
        return str(user.id)
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(
    limiter: RateLimiter,
    identifier: str,
    max_requests: int,
    window_seconds: int,
) -> None:
    """Raise HTTP 429 if the rate limit is exceeded."""
    if not limiter.is_allowed(identifier):
        remaining = limiter.get_remaining(identifier)
        raise HTTPException(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Rate limit exceeded."
                f" Max {max_requests} requests per {window_seconds}s"
            ),
            headers={
                "X-RateLimit-Limit": str(max_requests),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(int(time.time() + window_seconds)),
            },
        )


def _apply_rate_limit_headers(
    response: object,
    limiter: RateLimiter,
    identifier: str,
    max_requests: int,
    window_seconds: int,
) -> None:
    """Attach X-RateLimit-* headers to *response* if it supports them."""
    headers = getattr(response, "headers", None)
    if headers is not None:
        remaining = limiter.get_remaining(identifier)
        headers["X-RateLimit-Limit"] = str(max_requests)
        headers["X-RateLimit-Remaining"] = str(remaining)
        headers["X-RateLimit-Reset"] = str(int(time.time() + window_seconds))


def rate_limit(
    max_requests: int = 100,
    window_seconds: int = 60,
    identifier_fn: Callable[[Request], str] | None = None,
) -> Callable[..., Any]:
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

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def async_wrapper(
            request: Request, *args: object, **kwargs: object
        ) -> object:
            identifier = _resolve_identifier(request, identifier_fn)
            _enforce_rate_limit(limiter, identifier, max_requests, window_seconds)
            response = await func(request, *args, **kwargs)
            _apply_rate_limit_headers(
                response, limiter, identifier, max_requests, window_seconds
            )
            return response

        @wraps(func)
        def sync_wrapper(request: Request, *args: object, **kwargs: object) -> object:
            identifier = _resolve_identifier(request, identifier_fn)
            _enforce_rate_limit(limiter, identifier, max_requests, window_seconds)
            response = func(request, *args, **kwargs)
            _apply_rate_limit_headers(
                response, limiter, identifier, max_requests, window_seconds
            )
            return response

        # Return appropriate wrapper based on function type
        import inspect

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator
