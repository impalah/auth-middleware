from typing import List

from fastapi import HTTPException, Request

from auth_middleware.logging import logger
from auth_middleware.settings import settings
from auth_middleware.types.user import User


class GroupChecker:
    """Controls if user has the required group (user_type)"""

    __allowed_groups: list = []

    def __init__(self, allowed_groups: List):
        self.__allowed_groups = allowed_groups

    async def __call__(self, request: Request):

        if settings.AUTH_MIDDLEWARE_DISABLED:
            return

        if not hasattr(request.state, "current_user") or not request.state.current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        user: User = request.state.current_user
        groups: List[str] = await user.groups

        if groups is not None and not any(
            group in self.__allowed_groups for group in groups
        ):
            logger.debug(f"User with groups {groups} not in {self.__allowed_groups}")
            raise HTTPException(status_code=403, detail="Operation not allowed")
