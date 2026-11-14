from __future__ import annotations

import asyncio
from abc import ABCMeta, abstractmethod
from time import time_ns
from typing import TYPE_CHECKING, Any

from joserfc.jwt import JWTClaimsRegistry

from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.logging import logger
from auth_middleware.types.jwt import JWK, JWKS, JWTAuthorizationCredentials
from auth_middleware.types.user import User

if TYPE_CHECKING:
    from auth_middleware.contracts.groups_provider import GroupsProvider
    from auth_middleware.contracts.permissions_provider import PermissionsProvider
    from auth_middleware.contracts.roles_provider import RolesProvider
    from auth_middleware.providers.aws.jwt_provider_settings import (
        JWTProviderSettings,
    )


#: Back-off before retrying a failed JWKS refresh while stale keys are served.
_JWKS_RETRY_SECONDS = 30


class JWTProvider(metaclass=ABCMeta):
    """Abstract contract for a JWT authentication provider.

    Subclass this to implement support for a specific JWT issuer (Cognito,
    Entra ID, generic JWKS endpoint, etc.).  Concrete implementations must
    override :meth:`load_jwks`, :meth:`verify_token`, and
    :meth:`create_user_from_token`.
    """

    _settings: JWTProviderSettings | None
    _permissions_provider: PermissionsProvider | None
    _groups_provider: GroupsProvider | None
    _roles_provider: RolesProvider | None
    _background_refresh_task: asyncio.Task[None] | None

    def __init__(
        self,
        settings: JWTProviderSettings | None = None,
        permissions_provider: PermissionsProvider | None = None,
        groups_provider: GroupsProvider | None = None,
        roles_provider: RolesProvider | None = None,
    ) -> None:
        self._settings = settings
        self._permissions_provider = permissions_provider
        self._groups_provider = groups_provider
        self._roles_provider = roles_provider
        self._background_refresh_task = None
        # Serialises reloads: when the cache expires, concurrent requests must not
        # each hit the identity provider (thundering herd).
        self._jwks_lock = asyncio.Lock()

    async def _reload_jwks_locked(self) -> None:
        """Reload the JWKS once, however many requests noticed the expiry.

        If the identity provider is unreachable and keys are already cached, keep
        serving them (stale keys beat locking every user out) and retry only after
        a short back-off instead of on every request.
        """
        lock = getattr(self, "_jwks_lock", None)
        if lock is None:  # subclasses that skip super().__init__
            lock = self._jwks_lock = asyncio.Lock()
        async with lock:
            if hasattr(self, "jks") and not self._needs_jwks_refresh():
                return  # another request reloaded while we waited for the lock
            try:
                self.jks = await self.load_jwks()
            except InvalidTokenException:
                if not hasattr(self, "jks"):
                    raise
                logger.warning(
                    "JWKS refresh failed; serving cached keys, retry in {}s",
                    _JWKS_RETRY_SECONDS,
                )
                self.jks.timestamp = time_ns() + _JWKS_RETRY_SECONDS * 1_000_000_000
                self.jks.usage_counter = max(self.jks.usage_counter or 0, 100)

    async def aclose(self) -> None:
        """Cancel the background JWKS refresh task (call it on application shutdown)."""
        task = self._background_refresh_task
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._background_refresh_task = None

    async def _get_jwks(self) -> JWKS | None:
        """
        Returns a structure that caches the public keys used by the auth
        provider to sign its JWT tokens.
        Cache is refreshed after a settable time or number of reads (usages)
        based on the configured strategy.
        """
        try:
            if self._cache_is_unusable() or self._needs_jwks_refresh():
                await self._reload_jwks_locked()
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

    def _cache_is_unusable(self) -> bool:
        """True when there is no cached JWKS (first use) or it has no metadata."""
        return (
            not hasattr(self, "jks")
            or self.jks.timestamp is None
            or self.jks.usage_counter is None
        )

    def _time_expired(self) -> bool:
        return self.jks.timestamp is not None and self.jks.timestamp < time_ns()

    def _usage_exhausted(self) -> bool:
        return self.jks.usage_counter is not None and self.jks.usage_counter <= 0

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
            if self.jks.timestamp is None or self.jks.usage_counter is None:
                return True
            return self._time_expired() or self._usage_exhausted()

        strategy = getattr(self._settings, "jwks_cache_strategy", "both")
        by_time = strategy in ("time", "both") and self._time_expired()
        by_usage = strategy in ("usage", "both") and self._usage_exhausted()
        return by_time or by_usage

    def _schedule_background_refresh(self) -> None:
        """Schedules JWKS refresh in background before cache expires."""
        if self._background_refresh_task and not self._background_refresh_task.done():
            logger.debug("Background refresh task already running")
            return

        if not hasattr(self, "jks") or not self._settings:
            return

        self._background_refresh_task = asyncio.create_task(self._background_refresh())
        logger.debug("Background JWKS refresh task scheduled")

    async def _background_refresh(self) -> None:
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
            cache_expiry: int = (
                self.jks.timestamp
                if hasattr(self.jks, "timestamp") and self.jks.timestamp is not None
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
        # A token without a "kid" header cannot be matched to a key: that is a bad
        # token (the caller answers 401), not a server error.
        token_kid = token.header.get("kid")
        if token_kid is None:
            return None
        jwks: JWKS | None = await self._get_jwks()
        if jwks is not None and jwks.keys is not None:
            for key in jwks.keys:
                if key.get("kid") == token_kid:
                    return key
        return None

    def _validate_registered_claims(
        self, claims: dict[str, Any], leeway: int = 0
    ) -> None:
        """Validate standard registered JWT claims that signature
        verification alone does not check.

        A verified signature only proves the token was not tampered with —
        it says nothing about whether the token has expired. This must be
        called by every concrete provider's ``verify_token`` after a
        successful signature check, so an expired-but-validly-signed token
        is never accepted.

        ``exp`` is required (raises if absent); ``nbf``/``iat`` are also
        validated automatically by :class:`JWTClaimsRegistry` if present in
        ``claims``.

        Args:
            claims (dict[str, Any]): The token's decoded claims.
            leeway (int): Clock-skew allowance in seconds. Defaults to 0.

        Raises:
            joserfc.errors.JoseError: if ``exp`` is missing, the token has
                expired, or ``nbf``/``iat`` are invalid.
        """
        registry = JWTClaimsRegistry(exp={"essential": True}, leeway=leeway)
        registry.validate(claims)

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
