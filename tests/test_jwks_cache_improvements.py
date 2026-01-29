"""Tests for JWKS Cache Improvements."""

import asyncio
from time import time_ns

import pytest

from auth_middleware.providers.authn.jwt_provider import JWTProvider
from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings
from auth_middleware.types.jwt import JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User


class MockJWTProvider(JWTProvider):
    """Mock JWT Provider for testing cache functionality."""

    def __init__(self, settings=None, **kwargs):
        super().__init__(settings=settings, **kwargs)
        self.load_jwks_call_count = 0
        self.mock_jwks = JWKS(
            keys=[{"kid": "test-key", "kty": "RSA"}],
            timestamp=time_ns() + (20 * 60 * 1_000_000_000),  # 20 minutes from now
            usage_counter=1000,
        )

    async def load_jwks(self) -> JWKS:
        """Mock implementation that counts calls."""
        self.load_jwks_call_count += 1
        return JWKS(
            keys=[{"kid": f"test-key-{self.load_jwks_call_count}", "kty": "RSA"}],
            timestamp=time_ns() + (20 * 60 * 1_000_000_000),
            usage_counter=1000,
        )

    async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
        return True

    async def create_user_from_token(self, token: JWTAuthorizationCredentials) -> User:
        return User(id="test-user", email="test@example.com")


class TestJWKSCacheStrategy:
    """Test suite for JWKS cache strategy settings."""

    def test_default_settings(self):
        """Test default cache strategy settings."""
        settings = JWTProviderSettings()

        assert settings.jwks_cache_strategy == "both"
        assert settings.jwks_background_refresh is True
        assert settings.jwks_background_refresh_threshold == 0.8

    def test_time_only_strategy(self):
        """Test time-only cache strategy."""
        settings = JWTProviderSettings(jwks_cache_strategy="time")

        assert settings.jwks_cache_strategy == "time"

    def test_usage_only_strategy(self):
        """Test usage-only cache strategy."""
        settings = JWTProviderSettings(jwks_cache_strategy="usage")

        assert settings.jwks_cache_strategy == "usage"

    def test_background_refresh_disabled(self):
        """Test disabling background refresh."""
        settings = JWTProviderSettings(jwks_background_refresh=False)

        assert settings.jwks_background_refresh is False

    def test_custom_refresh_threshold(self):
        """Test custom background refresh threshold."""
        settings = JWTProviderSettings(jwks_background_refresh_threshold=0.9)

        assert settings.jwks_background_refresh_threshold == 0.9


class TestJWKSCacheRefreshLogic:
    """Test suite for JWKS cache refresh logic."""

    @pytest.mark.asyncio
    async def test_initial_load(self):
        """Test JWKS loads on first access."""
        provider = MockJWTProvider(settings=JWTProviderSettings())

        jwks = await provider._get_jwks()

        assert jwks is not None
        assert provider.load_jwks_call_count == 1
        assert len(jwks.keys) == 1

    @pytest.mark.asyncio
    async def test_cache_reuse(self):
        """Test JWKS is cached and reused."""
        provider = MockJWTProvider(settings=JWTProviderSettings())

        # First load
        jwks1 = await provider._get_jwks()
        # Second load (should use cache)
        jwks2 = await provider._get_jwks()

        assert provider.load_jwks_call_count == 1
        assert jwks1.keys[0]["kid"] == jwks2.keys[0]["kid"]

    @pytest.mark.asyncio
    async def test_time_based_refresh(self):
        """Test time-based cache refresh."""
        settings = JWTProviderSettings(
            jwks_cache_strategy="time",
            jwks_background_refresh=False,
        )
        provider = MockJWTProvider(settings=settings)

        # Initial load
        await provider._get_jwks()
        assert provider.load_jwks_call_count == 1

        # Force timestamp expiry
        provider.jks.timestamp = time_ns() - 1

        # Should reload
        await provider._get_jwks()
        assert provider.load_jwks_call_count == 2

    @pytest.mark.asyncio
    async def test_usage_based_refresh(self):
        """Test usage-based cache refresh."""
        settings = JWTProviderSettings(
            jwks_cache_strategy="usage",
            jwks_background_refresh=False,
        )
        provider = MockJWTProvider(settings=settings)

        # Initial load
        await provider._get_jwks()
        provider.jks.usage_counter = 2
        assert provider.load_jwks_call_count == 1

        # Use cache twice (decrements counter)
        await provider._get_jwks()  # counter = 1
        await provider._get_jwks()  # counter = 0
        assert provider.load_jwks_call_count == 1

        # Next access should reload
        await provider._get_jwks()
        assert provider.load_jwks_call_count == 2

    @pytest.mark.asyncio
    async def test_both_strategy_time_triggers(self):
        """Test 'both' strategy - time expiry triggers refresh."""
        settings = JWTProviderSettings(
            jwks_cache_strategy="both",
            jwks_background_refresh=False,
        )
        provider = MockJWTProvider(settings=settings)

        await provider._get_jwks()
        assert provider.load_jwks_call_count == 1

        # Expire timestamp (usage counter still valid)
        provider.jks.timestamp = time_ns() - 1
        provider.jks.usage_counter = 100

        await provider._get_jwks()
        assert provider.load_jwks_call_count == 2

    @pytest.mark.asyncio
    async def test_both_strategy_usage_triggers(self):
        """Test 'both' strategy - usage exhaustion triggers refresh."""
        settings = JWTProviderSettings(
            jwks_cache_strategy="both",
            jwks_background_refresh=False,
        )
        provider = MockJWTProvider(settings=settings)

        await provider._get_jwks()
        provider.jks.usage_counter = 1
        assert provider.load_jwks_call_count == 1

        # Exhaust usage (timestamp still valid)
        await provider._get_jwks()  # counter = 0
        assert provider.load_jwks_call_count == 1

        await provider._get_jwks()  # Should reload
        assert provider.load_jwks_call_count == 2


class TestBackgroundRefresh:
    """Test suite for background JWKS refresh."""

    @pytest.mark.asyncio
    async def test_background_refresh_scheduled(self):
        """Test background refresh task is scheduled."""
        settings = JWTProviderSettings(
            jwks_background_refresh=True,
            jwks_background_refresh_threshold=0.8,
        )
        provider = MockJWTProvider(settings=settings)

        await provider._get_jwks()

        assert provider._background_refresh_task is not None
        assert isinstance(provider._background_refresh_task, asyncio.Task)

    @pytest.mark.asyncio
    async def test_background_refresh_disabled(self):
        """Test no background refresh when disabled."""
        settings = JWTProviderSettings(jwks_background_refresh=False)
        provider = MockJWTProvider(settings=settings)

        await provider._get_jwks()

        assert provider._background_refresh_task is None

    @pytest.mark.asyncio
    async def test_background_refresh_executes(self):
        """Test background refresh actually refreshes JWKS."""
        settings = JWTProviderSettings(
            jwks_background_refresh=True,
            jwks_background_refresh_threshold=0.001,  # Very low threshold
        )
        provider = MockJWTProvider(settings=settings)

        # Override load_jwks to use short cache time
        original_load = provider.load_jwks

        async def short_cache_load():
            result = await original_load()
            # Set very short expiry (1 second in the future)
            result.timestamp = time_ns() + 1_000_000_000
            return result

        provider.load_jwks = short_cache_load

        # Initial load
        await provider._get_jwks()
        initial_count = provider.load_jwks_call_count

        # Wait for background refresh (should execute quickly with short cache time)
        await asyncio.sleep(0.3)

        # Background refresh should have executed
        assert provider.load_jwks_call_count > initial_count

    @pytest.mark.asyncio
    async def test_background_refresh_error_handling(self):
        """Test background refresh handles errors gracefully."""
        settings = JWTProviderSettings(
            jwks_background_refresh=True,
            jwks_background_refresh_threshold=0.01,
        )
        provider = MockJWTProvider(settings=settings)

        # Make load_jwks raise error on second call
        original_load = provider.load_jwks
        call_count = 0

        async def failing_load():
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                raise Exception("Simulated JWKS load failure")
            return await original_load()

        provider.load_jwks = failing_load

        # Initial load (succeeds)
        await provider._get_jwks()

        # Wait for background refresh (should fail but not crash)
        await asyncio.sleep(0.2)

        # Provider should still be functional
        assert provider.jks is not None

    @pytest.mark.asyncio
    async def test_only_one_background_task_runs(self):
        """Test only one background refresh task runs at a time."""
        settings = JWTProviderSettings(jwks_background_refresh=True)
        provider = MockJWTProvider(settings=settings)

        # Trigger multiple refreshes
        await provider._get_jwks()
        task1 = provider._background_refresh_task

        provider._schedule_background_refresh()
        task2 = provider._background_refresh_task

        # Should be same task
        assert task1 is task2


class TestNeedsJWKSRefresh:
    """Test suite for _needs_jwks_refresh method."""

    @pytest.mark.asyncio
    async def test_needs_refresh_no_cache(self):
        """Test needs refresh when no cache exists."""
        provider = MockJWTProvider(settings=JWTProviderSettings())

        needs_refresh = provider._needs_jwks_refresh()

        assert needs_refresh is True

    @pytest.mark.asyncio
    async def test_needs_refresh_time_expired(self):
        """Test needs refresh when time expired."""
        settings = JWTProviderSettings(jwks_cache_strategy="time")
        provider = MockJWTProvider(settings=settings)

        # Set up cache with expired timestamp
        provider.jks = JWKS(
            keys=[],
            timestamp=time_ns() - 1,
            usage_counter=100,
        )

        needs_refresh = provider._needs_jwks_refresh()

        assert needs_refresh is True

    @pytest.mark.asyncio
    async def test_needs_refresh_usage_exhausted(self):
        """Test needs refresh when usage exhausted."""
        settings = JWTProviderSettings(jwks_cache_strategy="usage")
        provider = MockJWTProvider(settings=settings)

        # Set up cache with exhausted usage
        provider.jks = JWKS(
            keys=[],
            timestamp=time_ns() + 1_000_000_000,
            usage_counter=0,
        )

        needs_refresh = provider._needs_jwks_refresh()

        assert needs_refresh is True

    @pytest.mark.asyncio
    async def test_does_not_need_refresh(self):
        """Test does not need refresh when cache is valid."""
        settings = JWTProviderSettings(jwks_cache_strategy="both")
        provider = MockJWTProvider(settings=settings)

        # Set up valid cache
        provider.jks = JWKS(
            keys=[],
            timestamp=time_ns() + (20 * 60 * 1_000_000_000),
            usage_counter=500,
        )

        needs_refresh = provider._needs_jwks_refresh()

        assert needs_refresh is False

    @pytest.mark.asyncio
    async def test_fallback_without_settings(self):
        """Test fallback behavior when no settings provided."""
        provider = MockJWTProvider(settings=None)

        # Set up cache
        provider.jks = JWKS(
            keys=[],
            timestamp=time_ns() - 1,  # Expired
            usage_counter=100,
        )

        # Should fall back to time-based check
        needs_refresh = provider._needs_jwks_refresh()

        assert needs_refresh is True
