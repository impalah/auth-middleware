from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException, Request

from auth_middleware.functions import get_current_user, require_groups, require_user
from auth_middleware.types.user import User


@patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False)
def test_require_groups_ok():
    allowed_groups = ["admin", "user"]

    # Mock the GroupChecker class
    mock_group_checker = MagicMock()

    # Patch the GroupChecker class to return the mock object
    with patch(
        "auth_middleware.functions.GroupChecker", return_value=mock_group_checker
    ):
        # Create a request object
        scope = {"type": "http"}
        request = Request(scope=scope)

        # Call the require_groups function
        group_checker = require_groups(allowed_groups)
        result = group_checker(request)

        # Assert that the GroupChecker class was called with the correct arguments
        mock_group_checker.assert_called_once_with(request)


@patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False)
def test_require_groups_not_logged_in():
    allowed_groups = ["admin", "user"]

    # Mock the GroupChecker class
    mock_group_checker = MagicMock()
    mock_group_checker.side_effect = HTTPException(
        status_code=401,
        detail="Authentication required",
    )

    # Patch the GroupChecker class to return the mock object
    with patch(
        "auth_middleware.functions.GroupChecker", return_value=mock_group_checker
    ):
        # Create a request object
        scope = {"type": "http"}
        request = Request(scope=scope)

        # Call the require_groups function
        group_checker = require_groups(allowed_groups)

        # Assert that an HTTPException is raised when the group_checker function is called
        with pytest.raises(HTTPException) as exc_info:
            result = group_checker(request)

        # Assert that the exception has the correct status code and detail
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Authentication required"


def test_require_user_not_logged_in():
    # Create a request object
    scope = {"type": "http"}
    request = Request(scope=scope)

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        # Call the require_user function
        user_checker = require_user()

        # Assert that calling the user_checker function raises an HTTPException
        try:
            user_checker(request)
        except HTTPException as e:
            assert e.status_code == 401
            assert e.detail == "Authentication required"


def test_require_user_ok():
    # Create a request object
    scope = {"type": "http"}
    request = Request(scope=scope)

    request.state.current_user = User(
        id="user_id",
        name="John Doe",
        groups=["admin"],
        email="mail@mail.com",
    )

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        # Call the require_user function
        user_checker = require_user()
        result = user_checker(request)

        assert result is None


def test_get_current_user_not_logged_in():
    # Create a request object
    scope = {"type": "http"}
    request = Request(scope=scope)

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        get_user = get_current_user()
        result = get_user(request)

        assert result is None


def test_get_current_user_user_ok():
    # Create a request object
    scope = {"type": "http"}
    request = Request(scope=scope)

    request.state.current_user = User(
        id="user_id",
        name="John Doe",
        groups=["admin"],
        email="mail@mail.com",
    )

    # Mock the settings.AUTH_MIDDLEWARE_DISABLED variable
    with patch("auth_middleware.functions.settings.AUTH_MIDDLEWARE_DISABLED", False):
        get_user = get_current_user()
        result = get_user(request)

        assert result is not None
        assert result.id == "user_id"
