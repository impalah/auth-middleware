"""
Example: JWKS Cache Strategies

This example demonstrates different JWKS caching strategies
for optimizing public key retrieval and validation performance.
"""

from fastapi import FastAPI

from auth_middleware import JwtAuthMiddleware
from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.cognito_provider import CognitoProvider

app = FastAPI(title="JWKS Cache Example")


# Example 1: Time-based caching only
time_based_settings = CognitoAuthzProviderSettings(
    user_pool_id="us-east-1_example",
    user_pool_region="us-east-1",
    user_pool_client_id="your-client-id",
    jwks_cache_strategy="time",  # Only time-based refresh
    jwks_cache_interval=20,  # Refresh every 20 minutes
    jwks_background_refresh=False,  # No background refresh
)

time_based_provider = CognitoProvider(settings=time_based_settings)


# Example 2: Usage-based caching only
usage_based_settings = CognitoAuthzProviderSettings(
    user_pool_id="us-east-1_example",
    user_pool_region="us-east-1",
    user_pool_client_id="your-client-id",
    jwks_cache_strategy="usage",  # Only usage-based refresh
    jwks_cache_usages=1000,  # Refresh after 1000 validations
    jwks_background_refresh=False,
)

usage_based_provider = CognitoProvider(settings=usage_based_settings)


# Example 3: Combined strategy (default)
combined_settings = CognitoAuthzProviderSettings(
    user_pool_id="us-east-1_example",
    user_pool_region="us-east-1",
    user_pool_client_id="your-client-id",
    jwks_cache_strategy="both",  # Both time AND usage
    jwks_cache_interval=20,  # Refresh after 20 minutes OR
    jwks_cache_usages=1000,  # 1000 validations (whichever comes first)
    jwks_background_refresh=False,
)

combined_provider = CognitoProvider(settings=combined_settings)


# Example 4: Background refresh enabled (recommended)
background_settings = CognitoAuthzProviderSettings(
    user_pool_id="us-east-1_example",
    user_pool_region="us-east-1",
    user_pool_client_id="your-client-id",
    jwks_cache_strategy="both",
    jwks_cache_interval=20,
    jwks_cache_usages=1000,
    jwks_background_refresh=True,  # Enable background refresh
    jwks_background_refresh_threshold=0.8,  # Refresh at 80% of cache lifetime
)

background_provider = CognitoProvider(settings=background_settings)


# Example 5: High-traffic configuration
high_traffic_settings = CognitoAuthzProviderSettings(
    user_pool_id="us-east-1_example",
    user_pool_region="us-east-1",
    user_pool_client_id="your-client-id",
    jwks_cache_strategy="both",
    jwks_cache_interval=30,  # Longer cache time
    jwks_cache_usages=10000,  # Higher usage threshold
    jwks_background_refresh=True,
    jwks_background_refresh_threshold=0.9,  # Aggressive background refresh
)

high_traffic_provider = CognitoProvider(settings=high_traffic_settings)


# Example 6: Low-traffic / high-security configuration
secure_settings = CognitoAuthzProviderSettings(
    user_pool_id="us-east-1_example",
    user_pool_region="us-east-1",
    user_pool_client_id="your-client-id",
    jwks_cache_strategy="time",  # Only time-based
    jwks_cache_interval=5,  # Refresh every 5 minutes
    jwks_background_refresh=True,
    jwks_background_refresh_threshold=0.5,  # Early refresh
)

secure_provider = CognitoProvider(settings=secure_settings)


# Choose provider based on your needs
# For this example, use the background refresh provider
auth_provider = background_provider

app.add_middleware(JwtAuthMiddleware, auth_provider=auth_provider)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "JWKS Cache Example",
        "cache_strategy": "both",
        "background_refresh": True,
    }


@app.get("/cache-info")
async def cache_info():
    """Information about current cache configuration."""
    settings = auth_provider._settings

    return {
        "strategy": settings.jwks_cache_strategy,
        "cache_interval_minutes": settings.jwks_cache_interval,
        "cache_usages": settings.jwks_cache_usages,
        "background_refresh": settings.jwks_background_refresh,
        "background_refresh_threshold": settings.jwks_background_refresh_threshold,
        "recommendations": {
            "time_based": "Use for predictable refresh schedules",
            "usage_based": "Use for highly variable traffic",
            "both": "Recommended for most applications",
            "background_refresh": "Enable to prevent cache expiry delays",
        },
    }


@app.get("/cache-strategies")
async def cache_strategies_guide():
    """Guide to choosing the right cache strategy."""
    return {
        "strategies": {
            "time": {
                "description": "Refresh cache based on time elapsed",
                "pros": ["Predictable refresh schedule", "Simple to reason about"],
                "cons": [
                    "May refresh unnecessarily during low traffic",
                    "May not refresh quickly enough during high traffic",
                ],
                "use_case": "Applications with consistent traffic patterns",
            },
            "usage": {
                "description": "Refresh cache after N token validations",
                "pros": [
                    "Adapts to traffic volume",
                    "No unnecessary refreshes during idle periods",
                ],
                "cons": [
                    "Unpredictable refresh timing",
                    "May go long periods without refresh during low traffic",
                ],
                "use_case": "Applications with highly variable traffic",
            },
            "both": {
                "description": "Refresh on time OR usage, whichever comes first",
                "pros": [
                    "Combines benefits of both strategies",
                    "Ensures timely refresh in all scenarios",
                ],
                "cons": ["Slightly more complex configuration"],
                "use_case": "Recommended for most production applications",
            },
        },
        "background_refresh": {
            "description": "Proactively refresh cache before expiry",
            "benefits": [
                "Prevents cache expiry delays",
                "Maintains consistent response times",
                "Reduces user-facing latency",
            ],
            "configuration": {
                "threshold": "0.8 means refresh at 80% of cache lifetime",
                "example": "With 20min interval and 0.8 threshold, refresh happens at 16min",
            },
            "recommendation": "Always enable for production",
        },
    }


if __name__ == "__main__":
    import uvicorn

    print("JWKS Cache Configuration:")
    print(f"- Strategy: {auth_provider._settings.jwks_cache_strategy}")
    print(f"- Cache Interval: {auth_provider._settings.jwks_cache_interval} minutes")
    print(f"- Cache Usages: {auth_provider._settings.jwks_cache_usages}")
    print(f"- Background Refresh: {auth_provider._settings.jwks_background_refresh}")
    print(
        f"- Refresh Threshold: {auth_provider._settings.jwks_background_refresh_threshold}"
    )

    uvicorn.run(app, host="0.0.0.0", port=8000)
