from collections.abc import Callable
from typing import Any

from fastapi import HTTPException, Request

from auth_middleware.guards.group_checker import GroupChecker
from auth_middleware.guards.permissions_checker import PermissionsChecker
from auth_middleware.guards.role_checker import RoleChecker
from auth_middleware.settings import settings
from auth_middleware.types.user import User


def require_permissions(allowed_permissions: list[str]) -> Callable[..., Any]:
    """Check if the user has the required permissions

    Args:
        allowed_permissions (List[str]): a list of required permissions
    """

    async def _permissions_checker(request: Request) -> None:
        """Calls the GroupChecker class to check if
        the user has the required permissions

        Args:
            request (Request): FastAPI request object

        Returns:
            GroupChecker: group checker object
        """
        checker = PermissionsChecker(allowed_permissions)
        await checker(request)

    return _permissions_checker


async def has_permissions(request: Request, allowed_permissions: list[str]) -> bool:
    """Check if the user has the required permissions asynchronously

    Args:
        request (Request): FastAPI request object
        allowed_permissions (List[str]): a list of required permissions

    Returns:
        bool: True if the user has the required permissions, False otherwise
    """
    checker = PermissionsChecker(allowed_permissions)
    try:
        await checker(request)
        return True
    except HTTPException:
        return False


def require_groups(allowed_groups: list[str]) -> Callable[..., Any]:
    """Check if the user has the required groups

    Args:
        allowed_groups (List[str]): a list of required groups
    """

    async def _group_checker(request: Request) -> None:
        """Calls the GroupChecker class to check if
        the user has the required groups

        Args:
            request (Request): FastAPI request object

        Returns:
            GroupChecker: group checker object
        """
        checker = GroupChecker(allowed_groups)
        await checker(request)

    return _group_checker


async def has_groups(request: Request, allowed_groups: list[str]) -> bool:
    """Check if the user has the required groups asynchronously

    Args:
        request (Request): FastAPI request object
        allowed_groups (List[str]): a list of required groups

    Returns:
        bool: True if the user has the required groups, False otherwise
    """
    checker = GroupChecker(allowed_groups=allowed_groups)
    try:
        await checker(request)
        return True
    except HTTPException:
        return False


def require_roles(allowed_roles: list[str]) -> Callable[..., Any]:
    """Check if the user has the required roles

    Args:
        allowed_roles (List[str]): a list of required roles
    """

    async def _role_checker(request: Request) -> None:
        """Calls the RoleChecker class to check if
        the user has the required roles

        Args:
            request (Request): FastAPI request object

        Returns:
            RoleChecker: role checker object
        """
        checker = RoleChecker(allowed_roles)
        await checker(request)

    return _role_checker


async def has_roles(request: Request, allowed_roles: list[str]) -> bool:
    """Check if the user has the required roles asynchronously

    Args:
        request (Request): FastAPI request object
        allowed_roles (List[str]): a list of required roles

    Returns:
        bool: True if the user has the required roles, False otherwise
    """
    checker = RoleChecker(allowed_roles=allowed_roles)
    try:
        await checker(request)
        return True
    except HTTPException:
        return False


def require_user() -> Callable[..., Any]:
    """Check if the user is authenticated"""

    def _user_checker(request: Request) -> User:
        if settings.AUTH_MIDDLEWARE_DISABLED:
            # Return a dummy user or raise an exception based on your needs
            raise HTTPException(status_code=401, detail="Authentication required")

        if not hasattr(request.state, "current_user") or not request.state.current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        return request.state.current_user  # type: ignore[no-any-return]

    return _user_checker


def get_current_user() -> Callable[..., Any]:
    """Returns the current user object if it exists"""

    def _get_user(request: Request) -> User | None:
        return (
            request.state.current_user
            if hasattr(request, "state") and hasattr(request.state, "current_user")
            else None
        )

    return _get_user
