from fastapi import HTTPException, Request

from auth_middleware.logging import logger
from auth_middleware.settings import settings
from auth_middleware.types.user import User


class PermissionsChecker:
    """Controls if user has the required permissions (user_type)"""

    def __init__(self, allowed_permissions: list[str], *, match: str = "any") -> None:
        if match not in ("any", "all"):
            raise ValueError("match must be 'any' or 'all'")
        self.__allowed_permissions = allowed_permissions
        self.__match_all = match == "all"

    async def __call__(self, request: Request) -> None:
        if settings.AUTH_MIDDLEWARE_DISABLED:
            return

        if not hasattr(request.state, "current_user") or not request.state.current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        user: User = request.state.current_user
        # A provider returning None must not mean "no restriction": fail closed.
        permissions: list[str] = (await user.permissions) or []

        held = set(permissions)
        satisfied = (
            all(item in held for item in self.__allowed_permissions)
            if self.__match_all
            else any(item in held for item in self.__allowed_permissions)
        )
        if not satisfied:
            logger.debug(
                f"User with permissions {permissions} not in "
                f"{self.__allowed_permissions}"
            )
            raise HTTPException(status_code=403, detail="Operation not allowed")
