"""Tests for Rate Limiter."""

import time
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException, Request

from auth_middleware.services.rate_limiter import RateLimiter, rate_limit


class TestRateLimiter:
    """Test suite for RateLimiter."""

    def test_initialization(self):
        """Test rate limiter initialization."""
        limiter = RateLimiter(max_requests=10, window_seconds=60)

        assert limiter.max_requests == 10
        assert limiter.window_seconds == 60
        assert len(limiter._requests) == 0

    def test_is_allowed_under_limit(self):
        """Test that requests under limit are allowed."""
        limiter = RateLimiter(max_requests=5, window_seconds=60)

        # First 5 requests should be allowed
        for i in range(5):
            assert limiter.is_allowed(f"user-{i}") is True

    def test_is_allowed_at_limit(self):
        """Test behavior at rate limit boundary."""
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        identifier = "user-123"

        # First 3 requests allowed
        assert limiter.is_allowed(identifier) is True
        assert limiter.is_allowed(identifier) is True
        assert limiter.is_allowed(identifier) is True

        # 4th request should be blocked
        assert limiter.is_allowed(identifier) is False

    def test_is_allowed_exceeds_limit(self):
        """Test that exceeding limit blocks requests."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        identifier = "user-456"

        assert limiter.is_allowed(identifier) is True
        assert limiter.is_allowed(identifier) is True
        assert limiter.is_allowed(identifier) is False
        assert limiter.is_allowed(identifier) is False

    def test_window_expiration(self):
        """Test that old requests expire after window."""
        limiter = RateLimiter(max_requests=2, window_seconds=1)  # 1 second window
        identifier = "user-789"

        # Use up limit
        assert limiter.is_allowed(identifier) is True
        assert limiter.is_allowed(identifier) is True
        assert limiter.is_allowed(identifier) is False

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        assert limiter.is_allowed(identifier) is True

    def test_get_remaining(self):
        """Test getting remaining requests."""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        identifier = "user-111"

        assert limiter.get_remaining(identifier) == 5

        limiter.is_allowed(identifier)
        assert limiter.get_remaining(identifier) == 4

        limiter.is_allowed(identifier)
        limiter.is_allowed(identifier)
        assert limiter.get_remaining(identifier) == 2

    def test_get_remaining_at_zero(self):
        """Test get_remaining when limit is exhausted."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        identifier = "user-222"

        limiter.is_allowed(identifier)
        limiter.is_allowed(identifier)

        assert limiter.get_remaining(identifier) == 0

    def test_reset(self):
        """Test resetting rate limit for identifier."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        identifier = "user-333"

        # Exhaust limit
        limiter.is_allowed(identifier)
        limiter.is_allowed(identifier)
        assert limiter.is_allowed(identifier) is False

        # Reset
        limiter.reset(identifier)

        # Should be allowed again
        assert limiter.is_allowed(identifier) is True

    def test_clear_all(self):
        """Test clearing all rate limit data."""
        limiter = RateLimiter(max_requests=5, window_seconds=60)

        # Add some requests
        limiter.is_allowed("user-1")
        limiter.is_allowed("user-2")
        limiter.is_allowed("user-3")

        assert len(limiter._requests) == 3

        # Clear all
        limiter.clear_all()

        assert len(limiter._requests) == 0

    def test_multiple_identifiers(self):
        """Test that different identifiers are tracked separately."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        # User 1 uses limit
        assert limiter.is_allowed("user-1") is True
        assert limiter.is_allowed("user-1") is True
        assert limiter.is_allowed("user-1") is False

        # User 2 should have full limit
        assert limiter.is_allowed("user-2") is True
        assert limiter.is_allowed("user-2") is True
        assert limiter.is_allowed("user-2") is False

    def test_sliding_window(self):
        """Test sliding window behavior."""
        limiter = RateLimiter(max_requests=2, window_seconds=2)
        identifier = "user-sliding"

        # Make first request
        assert limiter.is_allowed(identifier) is True

        # Wait 1 second
        time.sleep(1.0)

        # Make second request
        assert limiter.is_allowed(identifier) is True

        # Should be at limit
        assert limiter.is_allowed(identifier) is False

        # Wait 1.1 seconds (total 2.1s from first request)
        time.sleep(1.1)

        # First request should have expired
        assert limiter.is_allowed(identifier) is True

    def test_cleanup_old_entries(self):
        """Test that old entries are cleaned up."""
        limiter = RateLimiter(max_requests=10, window_seconds=1)
        identifier = "user-cleanup"

        # Make requests
        for _ in range(5):
            limiter.is_allowed(identifier)

        # Should have 5 entries
        assert len(limiter._requests[identifier]) == 5

        # Wait for expiration
        time.sleep(1.1)

        # Check remaining (triggers cleanup)
        remaining = limiter.get_remaining(identifier)

        # Old entries should be cleaned
        assert len(limiter._requests[identifier]) == 0
        assert remaining == 10


class TestRateLimitDecorator:
    """Test suite for rate_limit decorator."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock FastAPI request."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.current_user = MagicMock()
        request.state.current_user.id = "user-123"
        request.client = MagicMock()
        request.client.host = "192.168.1.1"
        return request

    @pytest.mark.asyncio
    async def test_decorator_allows_request(self, mock_request):
        """Test decorator allows requests under limit."""

        @rate_limit(max_requests=5, window_seconds=60)
        async def test_endpoint(request: Request):
            return {"status": "ok"}

        result = await test_endpoint(mock_request)
        assert result == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_decorator_blocks_excess_requests(self, mock_request):
        """Test decorator blocks requests exceeding limit."""

        @rate_limit(max_requests=2, window_seconds=60)
        async def test_endpoint(request: Request):
            return {"status": "ok"}

        # First 2 requests allowed
        await test_endpoint(mock_request)
        await test_endpoint(mock_request)

        # 3rd request blocked
        with pytest.raises(HTTPException) as exc_info:
            await test_endpoint(mock_request)

        assert exc_info.value.status_code == 429
        assert "Rate limit exceeded" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_decorator_custom_identifier(self, mock_request):
        """Test decorator with custom identifier function."""

        def get_ip(request: Request) -> str:
            return request.client.host

        @rate_limit(max_requests=2, window_seconds=60, identifier_fn=get_ip)
        async def test_endpoint(request: Request):
            return {"status": "ok"}

        # Should use IP address as identifier
        await test_endpoint(mock_request)
        await test_endpoint(mock_request)

        with pytest.raises(HTTPException) as exc_info:
            await test_endpoint(mock_request)

        assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_decorator_fallback_to_ip(self):
        """Test decorator falls back to IP when no user."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        # No current_user
        request.client = MagicMock()
        request.client.host = "10.0.0.1"

        @rate_limit(max_requests=2, window_seconds=60)
        async def test_endpoint(request: Request):
            return {"status": "ok"}

        await test_endpoint(request)
        await test_endpoint(request)

        with pytest.raises(HTTPException):
            await test_endpoint(request)

    @pytest.mark.asyncio
    async def test_decorator_includes_headers(self, mock_request):
        """Test that decorator includes rate limit headers."""

        @rate_limit(max_requests=5, window_seconds=60)
        async def test_endpoint(request: Request):
            response = MagicMock()
            response.headers = {}
            return response

        result = await test_endpoint(mock_request)

        # Check headers were added
        assert "X-RateLimit-Limit" in result.headers
        assert "X-RateLimit-Remaining" in result.headers
        assert "X-RateLimit-Reset" in result.headers

    @pytest.mark.asyncio
    async def test_decorator_exception_headers(self, mock_request):
        """Test exception includes rate limit headers."""

        @rate_limit(max_requests=1, window_seconds=60)
        async def test_endpoint(request: Request):
            return {"status": "ok"}

        await test_endpoint(mock_request)

        # Second request should raise exception with headers
        with pytest.raises(HTTPException) as exc_info:
            await test_endpoint(mock_request)

        exc = exc_info.value
        assert "X-RateLimit-Limit" in exc.headers
        assert "X-RateLimit-Remaining" in exc.headers
        assert "X-RateLimit-Reset" in exc.headers

    def test_decorator_sync_function(self, mock_request):
        """Test decorator works with synchronous functions."""

        @rate_limit(max_requests=2, window_seconds=60)
        def test_endpoint(request: Request):
            return {"status": "ok"}

        # First 2 requests allowed
        test_endpoint(mock_request)
        test_endpoint(mock_request)

        # 3rd blocked
        with pytest.raises(HTTPException) as exc_info:
            test_endpoint(mock_request)

        assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_decorator_independent_instances(self):
        """Test that different decorated functions have independent limiters."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.current_user = MagicMock()
        request.state.current_user.id = "user-999"

        @rate_limit(max_requests=1, window_seconds=60)
        async def endpoint_a(request: Request):
            return {"endpoint": "a"}

        @rate_limit(max_requests=1, window_seconds=60)
        async def endpoint_b(request: Request):
            return {"endpoint": "b"}

        # Each endpoint should have its own limit
        await endpoint_a(request)
        await endpoint_b(request)

        # Both should block on second call
        with pytest.raises(HTTPException):
            await endpoint_a(request)

        with pytest.raises(HTTPException):
            await endpoint_b(request)

    @pytest.mark.asyncio
    async def test_decorator_no_client_fallback(self):
        """Test decorator when request has no client."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.client = None

        @rate_limit(max_requests=2, window_seconds=60)
        async def test_endpoint(request: Request):
            return {"status": "ok"}

        # Should use "unknown" as identifier
        await test_endpoint(request)
        await test_endpoint(request)

        with pytest.raises(HTTPException):
            await test_endpoint(request)
