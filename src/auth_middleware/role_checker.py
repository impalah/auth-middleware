from fastapi import HTTPException, Request

from auth_middleware.logging import logger
from auth_middleware.settings import settings
from auth_middleware.types.user import User


class RoleChecker:
    """Controls if user has the required role (user_type)"""

    __allowed_roles: list[str] = []

    def __init__(self, allowed_roles: list[str]) -> None:
        self.__allowed_roles = allowed_roles

    async def __call__(self, request: Request) -> None:
        if settings.AUTH_MIDDLEWARE_DISABLED:
            return

        if not hasattr(request.state, "current_user") or not request.state.current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        user: User = request.state.current_user
        roles: list[str] = await user.roles

        if roles is not None and not any(
            role in self.__allowed_roles for role in roles
        ):
            logger.debug(f"User with roles {roles} not in {self.__allowed_roles}")
            raise HTTPException(status_code=403, detail="Operation not allowed")
