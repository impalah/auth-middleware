from typing import List

from fastapi import HTTPException, Request

from auth_middleware.group_checker import GroupChecker
from auth_middleware.permissions_checker import PermissionsChecker
from auth_middleware.settings import settings


def require_permissions(allowed_permissions: List[str]):
    """Check if the user has the required permissions

    Args:
        allowed_permissions (List[str]): a list of required permissions
    """

    async def _permissions_checker(request: Request):
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


def require_groups(allowed_groups: List[str]):
    """Check if the user has the required groups

    Args:
        allowed_groups (List[str]): a list of required groups
    """

    async def _group_checker(request: Request):
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


def require_user():
    """Check if the user is authenticated"""

    def _user_checker(request: Request):

        if settings.AUTH_MIDDLEWARE_DISABLED:
            return

        if not hasattr(request.state, "current_user") or not request.state.current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

    return _user_checker


def get_current_user():
    """Returns the current user object if it exists"""

    def _get_user(request: Request):

        return (
            request.state.current_user
            if hasattr(request.state, "current_user")
            else None
        )

    return _get_user
