from unittest.mock import patch

import pytest
from fastapi import HTTPException, Request

from auth_middleware.group_checker import GroupChecker
from auth_middleware.types.user import User


@pytest.mark.asyncio
async def test_group_checker_call_allowed_groups():
    allowed_groups = ["admin", "user"]

    scope = {"type": "http"}
    request: Request = Request(scope=scope)

    request.state.current_user = User(
        id="user_id",
        name="John Doe",
        email="mail@mail.com",
    )
    # Set groups directly for testing
    request.state.current_user._groups = ["admin"]

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch(
        "auth_middleware.group_checker.settings.AUTH_MIDDLEWARE_DISABLED", False
    ):
        checker = GroupChecker(allowed_groups)
        result = await checker(request)
        assert result is None


@pytest.mark.asyncio
async def test_group_checker_call_not_allowed_groups():
    allowed_groups = ["admin", "user"]

    scope = {"type": "http"}
    request: Request = Request(scope=scope)

    request.state.current_user = User(
        id="user_id",
        name="John Doe",
        email="mail@mail.com",
    )
    # Set groups directly for testing
    request.state.current_user._groups = ["guest"]

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch(
        "auth_middleware.group_checker.settings.AUTH_MIDDLEWARE_DISABLED", False
    ):
        checker = GroupChecker(allowed_groups)

        with pytest.raises(HTTPException) as exc_info:
            await checker(request)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "Operation not allowed"


@pytest.mark.asyncio
async def test_group_checker_call_no_current_user():
    allowed_groups = ["admin", "user"]

    scope = {"type": "http"}
    request: Request = Request(scope=scope)

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch(
        "auth_middleware.group_checker.settings.AUTH_MIDDLEWARE_DISABLED", False
    ):
        checker = GroupChecker(allowed_groups)

        with pytest.raises(HTTPException) as exc_info:
            await checker(request)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Authentication required"


@pytest.mark.asyncio
async def test_group_checker_call_middleware_disabled():
    allowed_groups = ["admin", "user"]

    scope = {"type": "http"}
    request: Request = Request(scope=scope)

    request.state.current_user = User(
        id="user_id",
        name="John Doe",
        email="mail@mail.com",
    )
    # Set groups directly for testing
    request.state.current_user._groups = ["guest"]

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.group_checker.settings.AUTH_MIDDLEWARE_DISABLED", True):
        checker = GroupChecker(allowed_groups)
        result = await checker(request)
        assert result is None
