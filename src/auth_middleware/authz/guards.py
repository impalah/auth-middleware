"""FastAPI guard ``require_permission`` and the non-raising ``has_permission``."""

from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable
from typing import Any

from loguru import logger
from starlette.requests import Request

from auth_middleware.authz.errors import (
    InvalidScopeError,
    PermissionDeniedError,
    ScopeNotVisibleError,
    StoreUnavailableError,
)
from auth_middleware.authz.runtime import (
    PERMISSION_ATTR,
    SCOPE_ATTR,
    Authz,
    DecisionEvent,
)
from auth_middleware.authz.scopes import GlobalScope, ScopeSource
from auth_middleware.authz.types import (
    MAX_PRINCIPAL_ID_LENGTH,
    AuthzContext,
    DecisionKind,
    Principal,
    ScopeRef,
)

AuthzSource = Authz | Callable[[Request], Authz] | None


def _resolve_authz(request: Request, authz: AuthzSource) -> Authz:
    if authz is None:
        return Authz.of(request)
    if isinstance(authz, Authz):
        return authz
    return authz(request)


async def _principal(request: Request, authz: Authz) -> Principal:
    user = getattr(request.state, "current_user", None)
    # "synthetic" is the placeholder of a disabled middleware; an empty or oversized
    # sub cannot be a real principal (and would only fail later, in the store).
    if (
        user is None
        or user.id == "synthetic"
        or not user.id
        or len(user.id) > MAX_PRINCIPAL_ID_LENGTH
    ):
        raise authz.error_policy.unauthenticated(request)
    groups = tuple(await user.groups or ())
    return Principal(id=user.id, groups=groups, email=user.email)


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "correlation_id", None) or request.headers.get(
        "x-request-id"
    )
    return str(value) if value else None


async def _emit(
    authz: Authz,
    request: Request,
    principal: Principal,
    permission: str,
    scope: ScopeRef,
    decision: DecisionKind,
    started: float,
    roles: frozenset[str] = frozenset(),
) -> None:
    """Deliver the decision to ``on_decision``.

    A failing hook is logged and swallowed: auditing must never turn an allowed
    request into a 500. An application that needs fail-closed auditing wraps its
    own dependency around this guard.
    """
    hook = authz.hooks.on_decision
    if hook is None:
        return
    try:
        event = DecisionEvent(
            kind=decision,
            principal_id=principal.id,
            scope=scope,
            permission=permission,
            roles=roles,
            sensitive=authz.catalog.spec(permission).sensitive,
            duration_ms=(time.perf_counter() - started) * 1000,
            request_id=_request_id(request),
        )
        result = hook(event)
        if inspect.isawaitable(result):
            await result
    except Exception:
        logger.opt(exception=True).error("authz on_decision hook failed (ignored)")


def require_permission(
    permission: str,
    *,
    scope: ScopeSource | None = None,
    authz: AuthzSource = None,
) -> Callable[..., Awaitable[AuthzContext]]:
    """Build a FastAPI dependency that enforces ``permission`` in ``scope``.

    The store factory is invoked lazily, when the dependency runs; FastAPI
    resolves the sub-dependencies of a route in declaration order, so a
    dependency that binds row-level security for the request must be declared
    before this guard.

    The guard never skips when ``AUTH_MIDDLEWARE_DISABLED`` is set: the
    synthetic user is rejected with 401.

    Args:
        permission: Permission name (a ``StrEnum`` member is accepted).
        scope: Where the scope comes from. Defaults to the global scope.
        authz: An ``Authz`` or a function of the request returning one; default
            ``Authz.of(request)`` (``app.state.authz``).

    Returns:
        A dependency returning the :class:`AuthzContext`.
    """
    name = str(permission)
    source: ScopeSource = scope or GlobalScope()

    async def dependency(request: Request) -> AuthzContext:
        started = time.perf_counter()
        rt = _resolve_authz(request, authz)
        principal = await _principal(request, rt)
        try:
            scope_ref = await source.resolve(request)
        except InvalidScopeError as exc:
            # e.g. an id longer than 200 chars: same answer as an unknown scope.
            raise rt.error_policy.not_visible(
                request, ScopeNotVisibleError(ScopeRef(exc.kind, "invalid"))
            ) from None
        try:
            authorizer = await rt.authorizer_for(request)
            ctx = await authorizer.authorize(principal, name, scope_ref)
        except StoreUnavailableError as exc:
            raise rt.error_policy.unavailable(request, exc) from None
        except ScopeNotVisibleError as exc:
            await _emit(
                rt,
                request,
                principal,
                name,
                scope_ref,
                DecisionKind.NOT_VISIBLE,
                started,
            )
            raise rt.error_policy.not_visible(request, exc) from None
        except PermissionDeniedError as exc:
            await _emit(
                rt, request, principal, name, scope_ref, DecisionKind.DENIED, started
            )
            raise rt.error_policy.denied(request, exc) from None
        await _emit(
            rt,
            request,
            principal,
            name,
            scope_ref,
            DecisionKind.ALLOWED,
            started,
            ctx.roles,
        )
        request.state.authz_context = ctx
        return ctx

    setattr(dependency, PERMISSION_ATTR, name)
    setattr(dependency, SCOPE_ATTR, source)
    return dependency


async def has_permission(
    request: Request,
    permission: str,
    scope: ScopeRef,
    *,
    authz: AuthzSource = None,
) -> bool:
    """Non-raising check for use inside handlers.

    Returns:
        ``True`` only if the authenticated principal holds ``permission`` in
        ``scope``; ``False`` for any other *request outcome* (not a member, denied,
        no user).

    Raises:
        AuthzError: For programming/configuration mistakes (unknown permission,
            scope-kind mismatch, role missing from the catalog...) and for an
            unavailable store: those are not answers, they are bugs or outages.
    """
    rt = _resolve_authz(request, authz)
    user = getattr(request.state, "current_user", None)
    if user is None or user.id == "synthetic":
        return False
    principal = await _principal(request, rt)
    authorizer = await rt.authorizer_for(request)
    return await authorizer.check(principal, str(permission), scope) is (
        DecisionKind.ALLOWED
    )


__all__: list[Any] = ["has_permission", "require_permission"]
