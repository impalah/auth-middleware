from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException, Request

from auth_middleware.guards.group_checker import GroupChecker
from auth_middleware.guards.permissions_checker import PermissionsChecker
from auth_middleware.guards.role_checker import RoleChecker
from auth_middleware.settings import settings
from auth_middleware.types.identity import Identity
from auth_middleware.types.user import User


def _check_match(match: str) -> None:
    if match not in ("any", "all"):
        raise ValueError("match must be 'any' or 'all'")


def require_permissions(
    allowed_permissions: list[str], *, match: str = "any"
) -> Callable[..., Any]:
    """Check if the user has the required permissions

    By default the user needs **at least one** of ``allowed_permissions``
    (``match="any"``, like ``require_groups`` and ``require_roles``); pass
    ``match="all"`` to require every one of them.

    Args:
        allowed_permissions (List[str]): a list of required permissions
    """
    _check_match(match)

    async def _permissions_checker(request: Request) -> None:
        """Calls the GroupChecker class to check if
        the user has the required permissions

        Args:
            request (Request): FastAPI request object

        Returns:
            GroupChecker: group checker object
        """
        checker = PermissionsChecker(allowed_permissions, match=match)
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


def require_groups(
    allowed_groups: list[str], *, match: str = "any"
) -> Callable[..., Any]:
    """Check if the user has the required groups

    Args:
        allowed_groups (List[str]): a list of required groups
    """
    _check_match(match)

    async def _group_checker(request: Request) -> None:
        """Calls the GroupChecker class to check if
        the user has the required groups

        Args:
            request (Request): FastAPI request object

        Returns:
            GroupChecker: group checker object
        """
        checker = GroupChecker(allowed_groups, match=match)
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


def require_roles(
    allowed_roles: list[str], *, match: str = "any"
) -> Callable[..., Any]:
    """Check if the user has the required roles

    Args:
        allowed_roles (List[str]): a list of required roles
    """
    _check_match(match)

    async def _role_checker(request: Request) -> None:
        """Calls the RoleChecker class to check if
        the user has the required roles

        Args:
            request (Request): FastAPI request object

        Returns:
            RoleChecker: role checker object
        """
        checker = RoleChecker(allowed_roles, match=match)
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
            # Consistent with require_groups/require_roles/require_permissions:
            # auth disabled means requests are never blocked. Prefer whatever
            # user the middleware already set (which is User.synthetic() when
            # disabled), falling back to it directly if state wasn't set at all.
            current_user = getattr(request.state, "current_user", None)
            return current_user or User.synthetic()

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


def _unauthenticated(
    request: Request, on_unauthenticated: Callable[[Request], Exception] | None
) -> Exception:
    if on_unauthenticated is not None:
        return on_unauthenticated(request)
    return HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _authenticated_user(
    request: Request,
    allow_synthetic: bool,
    on_unauthenticated: Callable[[Request], Exception] | None,
) -> User:
    user = getattr(request.state, "current_user", None)
    if not user or (user.id == "synthetic" and not allow_synthetic):
        raise _unauthenticated(request, on_unauthenticated)
    return user  # type: ignore[no-any-return]


def require_authenticated(
    *,
    allow_synthetic: bool = False,
    on_unauthenticated: Callable[[Request], Exception] | None = None,
) -> Callable[..., Awaitable[User]]:
    """Fail-closed authentication guard.

    Unlike :func:`require_user`, it never lets the request through when
    ``AUTH_MIDDLEWARE_DISABLED`` is set: the placeholder ``synthetic`` user the
    middleware creates then is rejected (401) unless ``allow_synthetic=True``.

    Args:
        allow_synthetic: Accept the placeholder user (development only).
        on_unauthenticated: Builds the exception to raise instead of the default
            ``401`` with ``WWW-Authenticate: Bearer`` (e.g. a uniform problem body).

    Returns:
        A dependency returning the authenticated :class:`User`.

    Raises:
        HTTPException: 401 when there is no user (or only the synthetic one).
    """

    async def _dependency(request: Request) -> User:
        return _authenticated_user(request, allow_synthetic, on_unauthenticated)

    return _dependency


def get_identity(
    *,
    allow_synthetic: bool = False,
    on_unauthenticated: Callable[[Request], Exception] | None = None,
) -> Callable[..., Awaitable[Identity]]:
    """Like :func:`require_authenticated` but returns an immutable :class:`Identity`.

    ``Identity.groups`` resolves the lazy ``await user.groups``; ``name`` falls back
    to the ``sub`` and ``email`` to ``""``.
    """

    async def _dependency(request: Request) -> Identity:
        user = _authenticated_user(request, allow_synthetic, on_unauthenticated)
        return Identity(
            sub=user.id,
            email=user.email or "",
            name=user.name or user.id,
            groups=tuple(await user.groups or ()),
        )

    return _dependency
