"""
Example: Metrics Collection

This example demonstrates how to collect and monitor
authentication metrics for performance monitoring and alerting.
"""

import time

from fastapi import Depends, FastAPI, Request

from auth_middleware import JwtAuthMiddleware
from auth_middleware.functions import require_user
from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.cognito_provider import CognitoProvider
from auth_middleware.services import MetricsCollector

app = FastAPI(title="Metrics Collection Example")

# Configure Cognito provider
settings = CognitoAuthzProviderSettings(
    user_pool_id="us-east-1_example",
    user_pool_region="us-east-1",
    user_pool_client_id="your-client-id",
)

auth_provider = CognitoProvider(settings=settings)
app.add_middleware(JwtAuthMiddleware, auth_provider=auth_provider)

# Initialize metrics collector
metrics = MetricsCollector()


# Example 1: Custom middleware to track all validations
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Middleware that records metrics for all requests."""
    start_time = time.time()

    try:
        response = await call_next(request)
        duration_ms = (time.time() - start_time) * 1000

        # Record successful validation if user is authenticated
        if hasattr(request.state, "current_user"):
            await metrics.record_validation_success(duration_ms)
        elif response.status_code == 401:
            # Record authentication failure
            await metrics.record_validation_failure("unauthorized", duration_ms)

        return response

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        error_type = type(e).__name__
        await metrics.record_validation_failure(error_type, duration_ms)
        raise


# Example 2: Metrics endpoint for monitoring
@app.get("/metrics")
async def get_metrics():
    """Get current authentication metrics."""
    return await metrics.get_metrics()


# Example 3: Prometheus-style metrics endpoint
@app.get("/metrics/prometheus")
async def prometheus_metrics():
    """Export metrics in Prometheus format."""
    snapshot = await metrics.get_metrics()

    # Convert to Prometheus format
    lines = [
        "# HELP auth_tokens_validated_total Total successfully validated tokens",
        "# TYPE auth_tokens_validated_total counter",
        f"auth_tokens_validated_total {snapshot['tokens_validated']}",
        "",
        "# HELP auth_tokens_failed_total Total failed token validations",
        "# TYPE auth_tokens_failed_total counter",
        f"auth_tokens_failed_total {snapshot['tokens_failed']}",
        "",
        "# HELP auth_success_rate Success rate percentage",
        "# TYPE auth_success_rate gauge",
        f"auth_success_rate {snapshot['success_rate']}",
        "",
        "# HELP auth_validation_duration_avg_ms Average validation time",
        "# TYPE auth_validation_duration_avg_ms gauge",
        f"auth_validation_duration_avg_ms {snapshot['validation_time_avg_ms']}",
        "",
        "# HELP auth_validation_duration_p95_ms P95 validation time",
        "# TYPE auth_validation_duration_p95_ms gauge",
        f"auth_validation_duration_p95_ms {snapshot['validation_time_p95_ms']}",
        "",
        "# HELP auth_validation_duration_p99_ms P99 validation time",
        "# TYPE auth_validation_duration_p99_ms gauge",
        f"auth_validation_duration_p99_ms {snapshot['validation_time_p99_ms']}",
        "",
    ]

    # Add error metrics
    for error_type, count in snapshot["errors_by_type"].items():
        lines.extend(
            [
                f"# HELP auth_errors_{error_type} Count of {error_type} errors",
                f"# TYPE auth_errors_{error_type} counter",
                f"auth_errors_{error_type} {count}",
                "",
            ]
        )

    return "\n".join(lines)


# Example 4: Health check with metrics
@app.get("/health")
async def health_check():
    """Health check with authentication metrics."""
    snapshot = await metrics.get_metrics()

    # Determine health based on metrics
    is_healthy = True
    warnings = []

    # Check success rate
    if snapshot["total_tokens"] > 100 and snapshot["success_rate"] < 95:
        warnings.append("Low authentication success rate")
        is_healthy = False

    # Check average validation time
    if snapshot["validation_time_avg_ms"] > 100:
        warnings.append("High average validation time")

    return {
        "status": "healthy" if is_healthy else "degraded",
        "warnings": warnings,
        "metrics": {
            "success_rate": snapshot["success_rate"],
            "avg_validation_ms": snapshot["validation_time_avg_ms"],
            "total_requests": snapshot["total_tokens"],
        },
    }


# Example 5: Admin endpoint to reset metrics
@app.post("/admin/metrics/reset")
async def reset_metrics():
    """Reset all metrics (admin only)."""
    await metrics.reset()
    return {"message": "Metrics reset successfully"}


# Example 6: Detailed metrics breakdown
@app.get("/admin/metrics/detailed")
async def detailed_metrics():
    """Get detailed metrics breakdown."""
    snapshot = await metrics.get_metrics()

    return {
        "overview": {
            "uptime_seconds": snapshot["uptime_seconds"],
            "uptime_hours": snapshot["uptime_seconds"] / 3600,
            "total_requests": snapshot["total_tokens"],
            "requests_per_second": snapshot["total_tokens"]
            / max(snapshot["uptime_seconds"], 1),
        },
        "success": {
            "count": snapshot["tokens_validated"],
            "rate": snapshot["success_rate"],
        },
        "failures": {
            "count": snapshot["tokens_failed"],
            "by_type": snapshot["errors_by_type"],
        },
        "performance": {
            "avg_ms": snapshot["validation_time_avg_ms"],
            "p95_ms": snapshot["validation_time_p95_ms"],
            "p99_ms": snapshot["validation_time_p99_ms"],
        },
    }


# Example 7: Alerting based on metrics
@app.get("/admin/metrics/alerts")
async def check_alerts():
    """Check for metric-based alerts."""
    snapshot = await metrics.get_metrics()
    alerts = []

    # High failure rate alert
    if snapshot["total_tokens"] > 50 and snapshot["success_rate"] < 90:
        alerts.append(
            {
                "level": "critical",
                "message": f"Low success rate: {snapshot['success_rate']:.2f}%",
                "metric": "success_rate",
                "value": snapshot["success_rate"],
                "threshold": 90,
            }
        )

    # Slow validation alert
    if snapshot["validation_time_p95_ms"] > 200:
        alerts.append(
            {
                "level": "warning",
                "message": f"Slow P95 validation time: {snapshot['validation_time_p95_ms']:.2f}ms",
                "metric": "validation_time_p95_ms",
                "value": snapshot["validation_time_p95_ms"],
                "threshold": 200,
            }
        )

    # High error rate for specific type
    for error_type, count in snapshot["errors_by_type"].items():
        if count > 10:
            alerts.append(
                {
                    "level": "warning",
                    "message": f"High {error_type} error count: {count}",
                    "metric": f"errors_{error_type}",
                    "value": count,
                    "threshold": 10,
                }
            )

    return {"alerts": alerts, "count": len(alerts)}


# Example protected endpoint
@app.get("/api/data", dependencies=[Depends(require_user())])
async def get_data(request: Request):
    """Example protected endpoint."""
    user = request.state.current_user
    return {"data": "secret data", "user": user.id}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
