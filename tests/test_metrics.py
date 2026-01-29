"""Tests for Metrics Collector."""

import asyncio

import pytest

from auth_middleware.services.metrics import MetricsCollector


class TestMetricsCollector:
    """Test suite for MetricsCollector."""

    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test metrics collector initializes correctly."""
        metrics = MetricsCollector()

        snapshot = await metrics.get_metrics()

        assert snapshot["tokens_validated"] == 0
        assert snapshot["tokens_failed"] == 0
        assert snapshot["total_tokens"] == 0
        assert snapshot["success_rate"] == 0.0
        assert snapshot["uptime_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_record_validation_success(self):
        """Test recording successful validations."""
        metrics = MetricsCollector()

        await metrics.record_validation_success(25.5)
        await metrics.record_validation_success(30.2)
        await metrics.record_validation_success(22.1)

        snapshot = await metrics.get_metrics()

        assert snapshot["tokens_validated"] == 3
        assert snapshot["tokens_failed"] == 0
        assert snapshot["total_tokens"] == 3
        assert snapshot["success_rate"] == 100.0

    @pytest.mark.asyncio
    async def test_record_validation_failure(self):
        """Test recording failed validations."""
        metrics = MetricsCollector()

        await metrics.record_validation_failure("expired_token", 15.3)
        await metrics.record_validation_failure("invalid_signature", 20.1)
        await metrics.record_validation_failure("expired_token", 18.7)

        snapshot = await metrics.get_metrics()

        assert snapshot["tokens_validated"] == 0
        assert snapshot["tokens_failed"] == 3
        assert snapshot["total_tokens"] == 3
        assert snapshot["success_rate"] == 0.0
        assert snapshot["errors_by_type"]["expired_token"] == 2
        assert snapshot["errors_by_type"]["invalid_signature"] == 1

    @pytest.mark.asyncio
    async def test_mixed_success_and_failure(self):
        """Test recording both successful and failed validations."""
        metrics = MetricsCollector()

        await metrics.record_validation_success(25.0)
        await metrics.record_validation_success(30.0)
        await metrics.record_validation_failure("expired_token", 15.0)
        await metrics.record_validation_success(28.0)

        snapshot = await metrics.get_metrics()

        assert snapshot["tokens_validated"] == 3
        assert snapshot["tokens_failed"] == 1
        assert snapshot["total_tokens"] == 4
        assert snapshot["success_rate"] == 75.0

    @pytest.mark.asyncio
    async def test_validation_time_average(self):
        """Test average validation time calculation."""
        metrics = MetricsCollector()

        await metrics.record_validation_success(10.0)
        await metrics.record_validation_success(20.0)
        await metrics.record_validation_success(30.0)

        snapshot = await metrics.get_metrics()

        assert snapshot["validation_time_avg_ms"] == 20.0

    @pytest.mark.asyncio
    async def test_validation_time_p95(self):
        """Test 95th percentile validation time."""
        metrics = MetricsCollector()

        # Record 100 values from 1 to 100
        for i in range(1, 101):
            await metrics.record_validation_success(float(i))

        snapshot = await metrics.get_metrics()

        # P95 should be around 95
        assert 94.0 <= snapshot["validation_time_p95_ms"] <= 96.0

    @pytest.mark.asyncio
    async def test_validation_time_p99(self):
        """Test 99th percentile validation time."""
        metrics = MetricsCollector()

        # Record 100 values from 1 to 100
        for i in range(1, 101):
            await metrics.record_validation_success(float(i))

        snapshot = await metrics.get_metrics()

        # P99 should be around 99
        assert 98.0 <= snapshot["validation_time_p99_ms"] <= 100.0

    @pytest.mark.asyncio
    async def test_percentiles_with_single_value(self):
        """Test percentile calculations with single value."""
        metrics = MetricsCollector()

        await metrics.record_validation_success(42.0)

        snapshot = await metrics.get_metrics()

        assert snapshot["validation_time_p95_ms"] == 42.0
        assert snapshot["validation_time_p99_ms"] == 42.0

    @pytest.mark.asyncio
    async def test_error_type_tracking(self):
        """Test error type categorization."""
        metrics = MetricsCollector()

        await metrics.record_validation_failure("expired_token", 10.0)
        await metrics.record_validation_failure("expired_token", 11.0)
        await metrics.record_validation_failure("invalid_signature", 12.0)
        await metrics.record_validation_failure("malformed_token", 13.0)
        await metrics.record_validation_failure("invalid_signature", 14.0)
        await metrics.record_validation_failure("invalid_signature", 15.0)

        snapshot = await metrics.get_metrics()

        assert snapshot["errors_by_type"]["expired_token"] == 2
        assert snapshot["errors_by_type"]["invalid_signature"] == 3
        assert snapshot["errors_by_type"]["malformed_token"] == 1
        assert len(snapshot["errors_by_type"]) == 3

    @pytest.mark.asyncio
    async def test_reset_metrics(self):
        """Test resetting metrics."""
        metrics = MetricsCollector()

        # Record some metrics
        await metrics.record_validation_success(25.0)
        await metrics.record_validation_failure("error", 30.0)

        # Verify metrics exist
        snapshot1 = await metrics.get_metrics()
        assert snapshot1["total_tokens"] == 2

        # Reset
        await metrics.reset()

        # Verify metrics cleared
        snapshot2 = await metrics.get_metrics()
        assert snapshot2["tokens_validated"] == 0
        assert snapshot2["tokens_failed"] == 0
        assert snapshot2["total_tokens"] == 0
        assert snapshot2["errors_by_type"] == {}
        assert len(snapshot2) > 0  # Still returns structure

    @pytest.mark.asyncio
    async def test_uptime_tracking(self):
        """Test uptime is tracked correctly."""
        metrics = MetricsCollector()

        # Small delay
        await asyncio.sleep(0.1)

        snapshot = await metrics.get_metrics()

        assert snapshot["uptime_seconds"] >= 0.1

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Test metrics collection under concurrent access."""
        metrics = MetricsCollector()

        # Create concurrent tasks
        async def record_successes():
            for _ in range(50):
                await metrics.record_validation_success(10.0)

        async def record_failures():
            for _ in range(30):
                await metrics.record_validation_failure("test_error", 15.0)

        # Run concurrently
        await asyncio.gather(
            record_successes(),
            record_failures(),
            record_successes(),
        )

        snapshot = await metrics.get_metrics()

        assert snapshot["tokens_validated"] == 100  # 50 + 50
        assert snapshot["tokens_failed"] == 30
        assert snapshot["total_tokens"] == 130
        assert snapshot["errors_by_type"]["test_error"] == 30

    @pytest.mark.asyncio
    async def test_empty_metrics_no_division_by_zero(self):
        """Test empty metrics don't cause division by zero."""
        metrics = MetricsCollector()

        snapshot = await metrics.get_metrics()

        assert snapshot["success_rate"] == 0.0
        assert snapshot["validation_time_avg_ms"] == 0.0
        assert snapshot["validation_time_p95_ms"] == 0.0
        assert snapshot["validation_time_p99_ms"] == 0.0
