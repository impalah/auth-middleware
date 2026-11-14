from fastapi import HTTPException, Request

from auth_middleware.logging import logger
from auth_middleware.settings import settings
from auth_middleware.types.user import User


class RoleChecker:
    """Controls if user has the required role (user_type)"""

    def __init__(self, allowed_roles: list[str], *, match: str = "any") -> None:
        if match not in ("any", "all"):
            raise ValueError("match must be 'any' or 'all'")
        self.__allowed_roles = allowed_roles
        self.__match_all = match == "all"

    async def __call__(self, request: Request) -> None:
        if settings.AUTH_MIDDLEWARE_DISABLED:
            return

        if not hasattr(request.state, "current_user") or not request.state.current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        user: User = request.state.current_user
        # A provider returning None must not mean "no restriction": fail closed.
        roles: list[str] = (await user.roles) or []

        held = set(roles)
        satisfied = (
            all(item in held for item in self.__allowed_roles)
            if self.__match_all
            else any(item in held for item in self.__allowed_roles)
        )
        if not satisfied:
            logger.debug(f"User with roles {roles} not in {self.__allowed_roles}")
            raise HTTPException(status_code=403, detail="Operation not allowed")
