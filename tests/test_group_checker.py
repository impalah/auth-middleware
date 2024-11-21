from unittest.mock import MagicMock, patch

from fastapi import HTTPException, Request

from auth_middleware.group_checker import GroupChecker
from auth_middleware.user import User


def test_group_checker_call_allowed_groups():
    allowed_groups = ["admin", "user"]

    scope = {"type": "http"}
    request: Request = Request(scope=scope)

    request.state.current_user = User(
        id="user_id",
        name="John Doe",
        groups=["admin"],
        email="mail@mail.com",
    )

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):

        checker = GroupChecker(allowed_groups)(request)
        assert checker == None


def test_group_checker_call_not_allowed_groups():
    allowed_groups = ["admin", "user"]

    scope = {"type": "http"}
    request: Request = Request(scope=scope)

    request.state.current_user = User(
        id="user_id",
        name="John Doe",
        groups=["guest"],
        email="mail@mail.com",
    )

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):

        try:
            checker = GroupChecker(allowed_groups)(request)
        except HTTPException as e:
            assert e.status_code == 403
            assert e.detail == "Operation not allowed"
        else:
            assert False, "Expected HTTPException to be raised"


def test_group_checker_call_no_current_user():

    allowed_groups = ["admin", "user"]

    scope = {"type": "http"}
    request: Request = Request(scope=scope)

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):

        try:
            checker = GroupChecker(allowed_groups)(request)
        except HTTPException as e:
            assert e.status_code == 401
            assert e.detail == "Authentication required"
        else:
            assert False, "Expected HTTPException to be raised"


def test_group_checker_call_middleware_disabled():
    allowed_groups = ["admin", "user"]

    scope = {"type": "http"}
    request: Request = Request(scope=scope)

    request.state.current_user = User(
        id="user_id",
        name="John Doe",
        groups=["guest"],
        email="mail@mail.com",
    )

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", True):

        checker = GroupChecker(allowed_groups)(request)
        assert checker == None
