"""
Metrics Collection for Authentication Middleware.

This module provides metrics collection for monitoring authentication
performance, success rates, and error tracking.
"""

import asyncio
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any


class MetricsCollector:
    """Collector for authentication and authorization metrics.

    Tracks:
    - Token validation success/failure counts
    - Validation timing (avg, p95, p99)
    - Error types and frequencies
    - Uptime

    Example:
        ```python
        metrics = MetricsCollector()

        # Record successful validation
        await metrics.record_validation_success(duration_ms=25.3)

        # Record failed validation
        await metrics.record_validation_failure("expired_token", duration_ms=12.1)

        # Get current metrics
        snapshot = await metrics.get_metrics()
        print(f"Success rate: {snapshot['success_rate']}%")
        ```
    """

    def __init__(self):
        """Initialize metrics collector."""
        self._tokens_validated = 0
        self._tokens_failed = 0
        self._validation_times: list[float] = []
        self._errors_by_type: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
        self._start_time = datetime.now(UTC)

    async def record_validation_success(self, duration_ms: float):
        """Record successful token validation.

        Args:
            duration_ms: Time taken to validate token in milliseconds
        """
        async with self._lock:
            self._tokens_validated += 1
            self._validation_times.append(duration_ms)

    async def record_validation_failure(self, error_type: str, duration_ms: float):
        """Record failed token validation.

        Args:
            error_type: Type/category of validation error
            duration_ms: Time taken before failure in milliseconds
        """
        async with self._lock:
            self._tokens_failed += 1
            self._errors_by_type[error_type] += 1
            self._validation_times.append(duration_ms)

    async def get_metrics(self) -> dict[str, Any]:
        """Get snapshot of current metrics.

        Returns:
            Dictionary containing all collected metrics:
            - uptime_seconds: Time since metrics collection started
            - tokens_validated: Count of successful validations
            - tokens_failed: Count of failed validations
            - total_tokens: Total tokens processed
            - success_rate: Percentage of successful validations
            - validation_time_avg_ms: Average validation time
            - validation_time_p95_ms: 95th percentile validation time
            - validation_time_p99_ms: 99th percentile validation time
            - errors_by_type: Dictionary of error types and counts
        """
        async with self._lock:
            uptime = (datetime.now(UTC) - self._start_time).total_seconds()

            return {
                "uptime_seconds": uptime,
                "tokens_validated": self._tokens_validated,
                "tokens_failed": self._tokens_failed,
                "total_tokens": self._tokens_validated + self._tokens_failed,
                "success_rate": self._calculate_success_rate(),
                "validation_time_avg_ms": self._calculate_avg_time(),
                "validation_time_p95_ms": self._calculate_p95_time(),
                "validation_time_p99_ms": self._calculate_p99_time(),
                "errors_by_type": dict(self._errors_by_type),
            }

    def _calculate_success_rate(self) -> float:
        """Calculate success rate percentage.

        Returns:
            Success rate between 0.0 and 100.0
        """
        total = self._tokens_validated + self._tokens_failed
        if total == 0:
            return 0.0
        return (self._tokens_validated / total) * 100

    def _calculate_avg_time(self) -> float:
        """Calculate average validation time.

        Returns:
            Average time in milliseconds
        """
        if not self._validation_times:
            return 0.0
        return sum(self._validation_times) / len(self._validation_times)

    def _calculate_p95_time(self) -> float:
        """Calculate 95th percentile validation time.

        Returns:
            P95 time in milliseconds
        """
        if not self._validation_times:
            return 0.0
        sorted_times = sorted(self._validation_times)
        index = int(len(sorted_times) * 0.95)
        if index >= len(sorted_times):
            index = len(sorted_times) - 1
        return sorted_times[index]

    def _calculate_p99_time(self) -> float:
        """Calculate 99th percentile validation time.

        Returns:
            P99 time in milliseconds
        """
        if not self._validation_times:
            return 0.0
        sorted_times = sorted(self._validation_times)
        index = int(len(sorted_times) * 0.99)
        if index >= len(sorted_times):
            index = len(sorted_times) - 1
        return sorted_times[index]

    async def reset(self):
        """Reset all metrics to initial state."""
        async with self._lock:
            self._tokens_validated = 0
            self._tokens_failed = 0
            self._validation_times = []
            self._errors_by_type = defaultdict(int)
            self._start_time = datetime.now(UTC)
