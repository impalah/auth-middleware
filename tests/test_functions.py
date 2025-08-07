"""
Comprehensive tests for auth_middleware.functions module.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException, Request
from starlette.datastructures import State

from auth_middleware.functions import (
    get_current_user,
    has_groups,
    has_permissions,
    require_groups,
    require_permissions,
    require_user,
)


class TestRequirePermissions:
    """Test cases for require_permissions function."""

    @pytest.mark.asyncio
    async def test_require_permissions_success(self, mock_request_with_user):
        """Test require_permissions with valid permissions."""
        # Setup user with permissions
        user = mock_request_with_user.state.current_user
        user._permissions = ["read", "write"]

        # Create permission checker
        permission_checker = require_permissions(["read"])
        checker_func = permission_checker

        # Mock PermissionsChecker
        with patch("auth_middleware.functions.PermissionsChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker.return_value = mock_checker_instance

            # Execute
            await checker_func(mock_request_with_user)

            # Verify
            mock_checker.assert_called_once_with(["read"])
            mock_checker_instance.assert_called_once_with(mock_request_with_user)

    @pytest.mark.asyncio
    async def test_require_permissions_failure(self, mock_request_with_user):
        """Test require_permissions with insufficient permissions."""
        # Setup user with limited permissions
        user = mock_request_with_user.state.current_user
        user._permissions = ["read"]

        # Create permission checker
        permission_checker = require_permissions(["admin"])
        checker_func = permission_checker

        # Mock PermissionsChecker to raise exception
        with patch("auth_middleware.functions.PermissionsChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker_instance.side_effect = HTTPException(
                status_code=403, detail="Operation not allowed"
            )
            mock_checker.return_value = mock_checker_instance

            # Execute and verify exception
            with pytest.raises(HTTPException) as exc_info:
                await checker_func(mock_request_with_user)

            assert exc_info.value.status_code == 403

    def test_require_permissions_returns_callable(self):
        """Test that require_permissions returns a callable."""
        result = require_permissions(["read"])
        assert callable(result)


class TestHasPermissions:
    """Test cases for has_permissions function."""

    @pytest.mark.asyncio
    async def test_has_permissions_true(self, mock_request_with_user):
        """Test has_permissions returns True for valid permissions."""
        with patch("auth_middleware.functions.PermissionsChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker.return_value = mock_checker_instance

            result = await has_permissions(mock_request_with_user, ["read"])

            assert result is True
            mock_checker.assert_called_once_with(["read"])
            mock_checker_instance.assert_called_once_with(mock_request_with_user)

    @pytest.mark.asyncio
    async def test_has_permissions_false(self, mock_request_with_user):
        """Test has_permissions returns False for insufficient permissions."""
        with patch("auth_middleware.functions.PermissionsChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker_instance.side_effect = HTTPException(status_code=403)
            mock_checker.return_value = mock_checker_instance

            result = await has_permissions(mock_request_with_user, ["admin"])

            assert result is False

    @pytest.mark.asyncio
    async def test_has_permissions_no_user(self, mock_request_without_user):
        """Test has_permissions with no authenticated user."""
        with patch("auth_middleware.functions.PermissionsChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker_instance.side_effect = HTTPException(status_code=401)
            mock_checker.return_value = mock_checker_instance

            result = await has_permissions(mock_request_without_user, ["read"])

            assert result is False


class TestRequireGroups:
    """Test cases for require_groups function."""

    @pytest.mark.asyncio
    async def test_require_groups_success(self, mock_request_with_user):
        """Test require_groups with valid groups."""
        # Setup user with groups
        user = mock_request_with_user.state.current_user
        user._groups = ["admin", "users"]

        # Create group checker
        group_checker = require_groups(["admin"])
        checker_func = group_checker

        # Mock GroupChecker
        with patch("auth_middleware.functions.GroupChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker.return_value = mock_checker_instance

            # Execute
            await checker_func(mock_request_with_user)

            # Verify
            mock_checker.assert_called_once_with(["admin"])
            mock_checker_instance.assert_called_once_with(mock_request_with_user)

    @pytest.mark.asyncio
    async def test_require_groups_failure(self, mock_request_with_user):
        """Test require_groups with insufficient groups."""
        # Setup user with limited groups
        user = mock_request_with_user.state.current_user
        user._groups = ["users"]

        # Create group checker
        group_checker = require_groups(["admin"])
        checker_func = group_checker

        # Mock GroupChecker to raise exception
        with patch("auth_middleware.functions.GroupChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker_instance.side_effect = HTTPException(
                status_code=403, detail="Operation not allowed"
            )
            mock_checker.return_value = mock_checker_instance

            # Execute and verify exception
            with pytest.raises(HTTPException) as exc_info:
                await checker_func(mock_request_with_user)

            assert exc_info.value.status_code == 403

    def test_require_groups_returns_callable(self):
        """Test that require_groups returns a callable."""
        result = require_groups(["admin"])
        assert callable(result)


class TestHasGroups:
    """Test cases for has_groups function."""

    @pytest.mark.asyncio
    async def test_has_groups_true(self, mock_request_with_user):
        """Test has_groups returns True for valid groups."""
        with patch("auth_middleware.functions.GroupChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker.return_value = mock_checker_instance

            result = await has_groups(mock_request_with_user, ["admin"])

            assert result is True
            mock_checker.assert_called_once_with(allowed_groups=["admin"])
            mock_checker_instance.assert_called_once_with(mock_request_with_user)

    @pytest.mark.asyncio
    async def test_has_groups_false(self, mock_request_with_user):
        """Test has_groups returns False for insufficient groups."""
        with patch("auth_middleware.functions.GroupChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker_instance.side_effect = HTTPException(status_code=403)
            mock_checker.return_value = mock_checker_instance

            result = await has_groups(mock_request_with_user, ["admin"])

            assert result is False

    @pytest.mark.asyncio
    async def test_has_groups_no_user(self, mock_request_without_user):
        """Test has_groups with no authenticated user."""
        with patch("auth_middleware.functions.GroupChecker") as mock_checker:
            mock_checker_instance = AsyncMock()
            mock_checker_instance.side_effect = HTTPException(status_code=401)
            mock_checker.return_value = mock_checker_instance

            result = await has_groups(mock_request_without_user, ["admin"])

            assert result is False


class TestRequireUser:
    """Test cases for require_user function."""

    def test_require_user_with_authenticated_user(self, mock_request_with_user):
        """Test require_user with authenticated user."""
        user_checker = require_user()
        checker_func = user_checker

        # Should not raise exception
        result = checker_func(mock_request_with_user)
        assert result is None

    def test_require_user_without_user(self, mock_request_without_user):
        """Test require_user without authenticated user."""
        user_checker = require_user()
        checker_func = user_checker

        # Should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            checker_func(mock_request_without_user)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Authentication required"

    def test_require_user_with_none_user(self):
        """Test require_user with None user."""
        request = Mock(spec=Request)
        request.state = State()
        request.state.current_user = None

        user_checker = require_user()
        checker_func = user_checker

        # Should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            checker_func(request)

        assert exc_info.value.status_code == 401

    def test_require_user_with_disabled_middleware(
        self, mock_request_without_user, mock_disabled_middleware
    ):
        """Test require_user with disabled middleware."""
        user_checker = require_user()
        checker_func = user_checker

        # Should not raise exception when middleware is disabled
        result = checker_func(mock_request_without_user)
        assert result is None

    def test_require_user_returns_callable(self):
        """Test that require_user returns a callable."""
        result = require_user()
        assert callable(result)


class TestGetCurrentUser:
    """Test cases for get_current_user function."""

    def test_get_current_user_with_user(self, mock_request_with_user, sample_user):
        """Test get_current_user with authenticated user."""
        user_getter = get_current_user()
        getter_func = user_getter

        result = getter_func(mock_request_with_user)

        assert result == sample_user
        assert result.id == "test-user-123"

    def test_get_current_user_without_user(self, mock_request_without_user):
        """Test get_current_user without authenticated user."""
        user_getter = get_current_user()
        getter_func = user_getter

        result = getter_func(mock_request_without_user)

        assert result is None

    def test_get_current_user_no_state(self):
        """Test get_current_user with request that has no state."""

        # Create a simple object without a state attribute
        class MockRequest:
            pass

        request = MockRequest()

        user_getter = get_current_user()
        getter_func = user_getter

        result = getter_func(request)

        assert result is None

    def test_get_current_user_returns_callable(self):
        """Test that get_current_user returns a callable."""
        result = get_current_user()
        assert callable(result)


class TestFunctionsIntegration:
    """Integration tests for functions working together."""

    @pytest.mark.asyncio
    async def test_multiple_requirements_together(self, mock_request_with_user):
        """Test multiple authentication requirements together."""
        # Setup user with both groups and permissions
        user = mock_request_with_user.state.current_user
        user._groups = ["admin"]
        user._permissions = ["read", "write"]

        # Test require_user
        user_checker = require_user()
        user_checker(mock_request_with_user)  # Should not raise

        # Test require_groups
        with patch("auth_middleware.functions.GroupChecker") as mock_group_checker:
            mock_group_checker_instance = AsyncMock()
            mock_group_checker.return_value = mock_group_checker_instance

            group_checker = require_groups(["admin"])
            await group_checker(mock_request_with_user)

        # Test require_permissions
        with patch("auth_middleware.functions.PermissionsChecker") as mock_perm_checker:
            mock_perm_checker_instance = AsyncMock()
            mock_perm_checker.return_value = mock_perm_checker_instance

            perm_checker = require_permissions(["read"])
            await perm_checker(mock_request_with_user)

    def test_function_parameters_validation(self):
        """Test that functions handle empty or invalid parameters."""
        # Empty lists should be valid
        assert callable(require_groups([]))
        assert callable(require_permissions([]))

        # Functions should be reusable
        group_checker1 = require_groups(["admin"])
        group_checker2 = require_groups(["user"])
        assert group_checker1 != group_checker2
