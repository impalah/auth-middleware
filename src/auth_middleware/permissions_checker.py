from typing import List

from fastapi import HTTPException, Request

from auth_middleware.logging import logger
from auth_middleware.settings import settings
from auth_middleware.types.user import User


class PermissionsChecker:
    """Controls if user has the required permissions (user_type)"""

    __allowed_permissions: list = []

    def __init__(self, allowed_permissions: List):
        self.__allowed_permissions = allowed_permissions

    async def __call__(self, request: Request):

        if settings.AUTH_MIDDLEWARE_DISABLED:
            return

        if not hasattr(request.state, "current_user") or not request.state.current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        user: User = request.state.current_user
        permissions: List[str] = await user.permissions

        if permissions is not None and not any(
            permissions in self.__allowed_permissions for permissions in permissions
        ):
            logger.debug(
                f"User with permissions {permissions} not in {self.__allowed_permissions}"
            )
            raise HTTPException(status_code=403, detail="Operation not allowed")
