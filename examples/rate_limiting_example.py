"""
Example: Rate Limiting

This example demonstrates how to use the built-in rate limiter
to protect endpoints from abuse.
"""

from fastapi import FastAPI, Request

from auth_middleware.services import RateLimiter, rate_limit

app = FastAPI(title="Rate Limiting Example")

# Create rate limiter instances
# Limit: 10 requests per minute
api_limiter = RateLimiter(max_requests=10, window_seconds=60)

# Limit: 100 requests per hour
data_limiter = RateLimiter(max_requests=100, window_seconds=3600)


# Example 1: Simple rate limiting with decorator
@app.get("/api/limited")
@rate_limit(max_requests=5, window_seconds=60)
async def limited_endpoint():
    """Endpoint limited to 5 requests per minute."""
    return {"message": "This endpoint is rate-limited"}


# Example 2: Rate limiting with custom identifier
@app.get("/api/user-limited")
@rate_limit(
    max_requests=10,
    window_seconds=60,
    identifier=lambda request: request.state.current_user.id
    if hasattr(request.state, "current_user")
    else request.client.host,
)
async def user_limited_endpoint(request: Request):
    """Endpoint with per-user rate limiting."""
    return {"message": "Rate limited per user"}


# Example 3: Manual rate limiting with RateLimiter class
@app.get("/api/manual-limit")
async def manual_limited_endpoint(request: Request):
    """Endpoint with manual rate limit checking."""
    client_id = request.client.host

    # Check if request is allowed
    if not await api_limiter.is_allowed(client_id):
        remaining = await api_limiter.get_remaining(client_id)
        return {
            "error": "Rate limit exceeded",
            "remaining": remaining,
            "retry_after": 60,
        }, 429

    # Process request
    return {"message": "Request accepted"}


# Example 4: Different limits for different endpoints
@app.get("/api/light")
@rate_limit(max_requests=100, window_seconds=60)
async def light_endpoint():
    """Light endpoint with higher limit."""
    return {"data": "quick response"}


@app.get("/api/heavy")
@rate_limit(max_requests=5, window_seconds=60)
async def heavy_endpoint():
    """Heavy endpoint with strict limit."""
    import time

    time.sleep(0.1)  # Simulate heavy processing
    return {"data": "processed data"}


# Example 5: Rate limiting with custom headers
@app.get("/api/with-headers")
async def headers_example(request: Request):
    """Endpoint that shows rate limit info in headers."""
    from fastapi.responses import JSONResponse

    client_id = request.client.host

    if not await api_limiter.is_allowed(client_id):
        remaining = await api_limiter.get_remaining(client_id)
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded"},
            headers={
                "X-RateLimit-Limit": "10",
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": "60",
            },
        )

    remaining = await api_limiter.get_remaining(client_id)

    return JSONResponse(
        content={"message": "Success"},
        headers={
            "X-RateLimit-Limit": "10",
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": "60",
        },
    )


# Example 6: Reset rate limits (admin endpoint)
@app.post("/admin/reset-limits")
async def reset_limits(client_id: str | None = None):
    """Reset rate limits for a specific client or all clients."""
    if client_id:
        await api_limiter.reset(client_id)
        return {"message": f"Rate limit reset for {client_id}"}
    else:
        await api_limiter.clear_all()
        return {"message": "All rate limits cleared"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
