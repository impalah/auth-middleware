import asyncio
from abc import ABCMeta, abstractmethod
from time import time_ns
from typing import TYPE_CHECKING

from auth_middleware.logging import logger
from auth_middleware.types.jwt import JWK, JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User

if TYPE_CHECKING:
    from auth_middleware.providers.authn.jwt_provider_settings import (
        JWTProviderSettings,
    )
    from auth_middleware.providers.authz.groups_provider import GroupsProvider
    from auth_middleware.providers.authz.permissions_provider import PermissionsProvider


class JWTProvider(metaclass=ABCMeta):
    """Basic interface for a JWT authentication provider

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    _settings: JWTProviderSettings | None
    _permissions_provider: PermissionsProvider | None
    _groups_provider: GroupsProvider | None
    _background_refresh_task: asyncio.Task | None

    def __init__(
        self,
        settings: JWTProviderSettings | None = None,
        permissions_provider: PermissionsProvider | None = None,
        groups_provider: GroupsProvider | None = None,
    ) -> None:
        self._settings = settings
        self._permissions_provider = permissions_provider
        self._groups_provider = groups_provider
        self._background_refresh_task = None

    async def _get_jwks(self) -> JWKS | None:
        """
        Returns a structure that caches the public keys used by the auth
        provider to sign its JWT tokens.
        Cache is refreshed after a settable time or number of reads (usages)
        based on the configured strategy.
        """
        reload_cache = False
        try:
            if (
                not hasattr(self, "jks")
                or self.jks.timestamp is None
                or self.jks.usage_counter is None
            ):
                reload_cache = True
            else:
                # Use new strategy-based refresh logic
                reload_cache = self._needs_jwks_refresh()
        except AttributeError:
            # the first time after application startup, self.jks is NOT defined
            reload_cache = True

        try:
            if reload_cache:
                self.jks: JWKS = await self.load_jwks()
                logger.debug("JWKS loaded")

                # Schedule background refresh if enabled
                if self._settings and getattr(
                    self._settings, "jwks_background_refresh", False
                ):
                    self._schedule_background_refresh()

            # Always decrement usage counter after accessing JWKS
            if hasattr(self, "jks") and self.jks.usage_counter is not None:
                self.jks.usage_counter -= 1

        except KeyError:
            return None

        return self.jks

    def _needs_jwks_refresh(self) -> bool:
        """
        Determines if JWKS cache needs refresh based on configured strategy.

        Returns:
            True if cache should be refreshed, False otherwise
        """
        if not hasattr(self, "jks"):
            return True

        if not self._settings:
            # Fallback to original behavior (both time and usage)
            time_expired = self.jks.timestamp < time_ns()
            usage_exhausted = self.jks.usage_counter <= 0
            return time_expired or usage_exhausted

        strategy = getattr(self._settings, "jwks_cache_strategy", "both")

        # Check time-based refresh
        if strategy in ["time", "both"]:
            if self.jks.timestamp < time_ns():
                return True

        # Check usage-based refresh
        if strategy in ["usage", "both"]:
            if self.jks.usage_counter <= 0:
                return True

        return False

    def _schedule_background_refresh(self):
        """Schedules JWKS refresh in background before cache expires."""
        if self._background_refresh_task and not self._background_refresh_task.done():
            logger.debug("Background refresh task already running")
            return

        if not hasattr(self, "jks") or not self._settings:
            return

        self._background_refresh_task = asyncio.create_task(self._background_refresh())
        logger.debug("Background JWKS refresh task scheduled")

    async def _background_refresh(self):
        """Refreshes JWKS in background before cache expires."""
        if not self._settings or not hasattr(self, "jks"):
            return

        try:
            # Calculate wait time based on threshold
            threshold = getattr(
                self._settings, "jwks_background_refresh_threshold", 0.8
            )
            cache_interval_minutes = getattr(self._settings, "jwks_cache_interval", 20)
            interval_ns = (
                cache_interval_minutes * 60 * 1_000_000_000
            )  # Convert to nanoseconds
            current_time = time_ns()

            # Calculate when cache will expire
            cache_expiry = (
                self.jks.timestamp
                if hasattr(self.jks, "timestamp")
                else current_time + interval_ns
            )
            time_until_expiry = (
                cache_expiry - current_time
            ) / 1_000_000_000  # Convert to seconds

            # Wait until threshold is reached
            wait_seconds = max(0, time_until_expiry * threshold)

            logger.debug(f"Background refresh will wait {wait_seconds:.2f} seconds")
            await asyncio.sleep(wait_seconds)

            # Refresh JWKS silently
            logger.info("Performing background JWKS refresh")
            new_jwks = await self.load_jwks()
            self.jks = new_jwks
            logger.info("Background JWKS refresh completed")

        except Exception as e:
            logger.warning(f"Background JWKS refresh failed: {e}")

    async def _get_hmac_key(self, token: JWTAuthorizationCredentials) -> JWK | None:
        jwks: JWKS | None = await self._get_jwks()
        if jwks is not None and jwks.keys is not None:
            for key in jwks.keys:
                if key["kid"] == token.header["kid"]:
                    return key
        return None

    @abstractmethod
    async def load_jwks(
        self,
    ) -> JWKS: ...

    @abstractmethod
    async def verify_token(
        self,
        token: JWTAuthorizationCredentials,
    ) -> bool: ...

    @abstractmethod
    async def create_user_from_token(
        self,
        token: JWTAuthorizationCredentials,
    ) -> User: ...
