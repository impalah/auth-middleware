"""Tests for RoleChecker."""

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from unittest.mock import AsyncMock, MagicMock, patch

from auth_middleware.role_checker import RoleChecker
from auth_middleware.types.user import User


def _make_request(user=None, has_user_attr: bool = True) -> Request:
    scope = {"type": "http"}
    request = Request(scope)
    if has_user_attr:
        request.state.current_user = user
    return request


class TestRoleCheckerDisabled:
    @pytest.mark.asyncio
    async def test_does_nothing_when_disabled(self):
        """When AUTH_MIDDLEWARE_DISABLED is True, no check is performed."""
        checker = RoleChecker(["admin"])
        request = _make_request(has_user_attr=False)

        with patch("auth_middleware.role_checker.settings.AUTH_MIDDLEWARE_DISABLED", True):
            await checker(request)  # should not raise


class TestRoleCheckerNoUser:
    @pytest.mark.asyncio
    async def test_raises_401_when_no_current_user_attr(self):
        """Missing current_user attribute raises 401."""
        checker = RoleChecker(["admin"])
        request = _make_request(has_user_attr=False)

        with patch("auth_middleware.role_checker.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(HTTPException) as exc_info:
                await checker(request)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_raises_401_when_current_user_is_none(self):
        """current_user = None raises 401."""
        checker = RoleChecker(["admin"])
        request = _make_request(user=None)

        with patch("auth_middleware.role_checker.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(HTTPException) as exc_info:
                await checker(request)
        assert exc_info.value.status_code == 401


class TestRoleCheckerAuthorized:
    @pytest.mark.asyncio
    async def test_passes_when_user_has_allowed_role(self):
        """User with a matching role is allowed through."""
        mock_user = MagicMock()
        mock_user.roles = AsyncMock(return_value=["admin", "viewer"])()

        checker = RoleChecker(["admin"])
        request = _make_request(user=mock_user)

        with patch("auth_middleware.role_checker.settings.AUTH_MIDDLEWARE_DISABLED", False):
            await checker(request)  # should not raise

    @pytest.mark.asyncio
    async def test_raises_403_when_user_lacks_role(self):
        """User without any matching role is forbidden."""
        mock_user = MagicMock()
        mock_user.roles = AsyncMock(return_value=["viewer"])()

        checker = RoleChecker(["admin"])
        request = _make_request(user=mock_user)

        with patch("auth_middleware.role_checker.settings.AUTH_MIDDLEWARE_DISABLED", False):
            with pytest.raises(HTTPException) as exc_info:
                await checker(request)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_passes_when_one_of_multiple_allowed_roles_matches(self):
        """Any matching role in the allowed list is sufficient."""
        mock_user = MagicMock()
        mock_user.roles = AsyncMock(return_value=["editor"])()

        checker = RoleChecker(["admin", "editor", "moderator"])
        request = _make_request(user=mock_user)

        with patch("auth_middleware.role_checker.settings.AUTH_MIDDLEWARE_DISABLED", False):
            await checker(request)  # should not raise

