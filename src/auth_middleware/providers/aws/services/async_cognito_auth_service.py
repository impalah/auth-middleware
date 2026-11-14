"""Async facade over :class:`CognitoAuthService` (boto3 is synchronous)."""

from __future__ import annotations

import asyncio
from typing import Any

from auth_middleware.providers.aws.services.cognito_auth_models import (
    ForgotPasswordResponse,
    LoginResponse,
    MeResponse,
    MessageResponse,
    TokenResponse,
    TotpSetupResponse,
)
from auth_middleware.providers.aws.services.cognito_auth_service import (
    CognitoAuthService,
)


class AsyncCognitoAuthService:
    """Runs every :class:`CognitoAuthService` call in a worker thread.

    boto3 is blocking: calling the sync service from an ``async def`` endpoint
    stalls the whole event loop for the duration of the network round trip. Use
    this wrapper from async code. Same arguments, same exceptions, awaitable results.

    Args:
        service: The synchronous service to delegate to.
    """

    def __init__(self, service: CognitoAuthService) -> None:
        self._service = service

    async def _run(self, name: str, *args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(getattr(self._service, name), *args, **kwargs)

    async def login(self, username: str, password: str) -> LoginResponse:
        """See :meth:`CognitoAuthService.login`."""
        return await self._run("login", username, password)  # type: ignore[no-any-return]

    async def respond_to_challenge(self, *args: Any, **kwargs: Any) -> Any:
        """See :meth:`CognitoAuthService.respond_to_challenge`."""
        return await self._run("respond_to_challenge", *args, **kwargs)

    async def logout(self, access_token: str) -> MessageResponse:
        """See :meth:`CognitoAuthService.logout`."""
        return await self._run("logout", access_token)  # type: ignore[no-any-return]

    async def refresh(self, refresh_token: str) -> TokenResponse:
        """See :meth:`CognitoAuthService.refresh`."""
        return await self._run("refresh", refresh_token)  # type: ignore[no-any-return]

    async def get_user(self, access_token: str) -> MeResponse:
        """See :meth:`CognitoAuthService.get_user`."""
        return await self._run("get_user", access_token)  # type: ignore[no-any-return]

    async def change_password(self, *args: Any, **kwargs: Any) -> MessageResponse:
        """See :meth:`CognitoAuthService.change_password`."""
        return await self._run("change_password", *args, **kwargs)  # type: ignore[no-any-return]

    async def forgot_password(self, username: str) -> ForgotPasswordResponse:
        """See :meth:`CognitoAuthService.forgot_password`."""
        return await self._run("forgot_password", username)  # type: ignore[no-any-return]

    async def reset_password(
        self, username: str, code: str, new_password: str
    ) -> MessageResponse:
        """See :meth:`CognitoAuthService.reset_password`."""
        return await self._run("reset_password", username, code, new_password)  # type: ignore[no-any-return]

    async def setup_totp(self, access_token: str) -> TotpSetupResponse:
        """See :meth:`CognitoAuthService.setup_totp`."""
        return await self._run("setup_totp", access_token)  # type: ignore[no-any-return]

    async def verify_totp(self, *args: Any, **kwargs: Any) -> MessageResponse:
        """See :meth:`CognitoAuthService.verify_totp`."""
        return await self._run("verify_totp", *args, **kwargs)  # type: ignore[no-any-return]

    async def disable_totp(self, access_token: str) -> MessageResponse:
        """See :meth:`CognitoAuthService.disable_totp`."""
        return await self._run("disable_totp", access_token)  # type: ignore[no-any-return]
