"""The ``Authz`` runtime: wiring injected at application startup."""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from loguru import logger
from starlette.applications import Starlette
from starlette.requests import Request

from auth_middleware.authz.catalog import PermissionCatalog
from auth_middleware.authz.engine import Authorizer
from auth_middleware.authz.errors import (
    ConfigurationError,
    PermissionDeniedError,
    ScopeNotVisibleError,
    StoreUnavailableError,
)
from auth_middleware.authz.ports import AssignmentStore, StoreFactory
from auth_middleware.authz.resolvers import (
    AssignmentRoleResolver,
    GroupRoleResolver,
    RoleResolver,
)
from auth_middleware.authz.types import (
    GLOBAL_KIND,
    DecisionKind,
    ScopeRef,
)
from auth_middleware.settings import settings

#: Attributes the guard puts on its dependency so routes can be validated.
PERMISSION_ATTR = "__authz_permission__"
SCOPE_ATTR = "__authz_scope__"


def default_not_visible(request: Request, exc: ScopeNotVisibleError) -> Exception:
    """404, identical for "not a member" and "does not exist"."""
    return HTTPException(status_code=404, detail="Not Found")


def default_denied(request: Request, exc: PermissionDeniedError) -> Exception:
    """403 naming the missing permission."""
    return HTTPException(
        status_code=403,
        detail={"error": "forbidden", "required_permission": exc.required},
    )


def default_unauthenticated(request: Request) -> Exception:
    """401 with a Bearer challenge."""
    return HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def default_unavailable(request: Request, exc: StoreUnavailableError) -> Exception:
    """503: the store is throttling or unreachable (an outage, not a decision)."""
    return HTTPException(
        status_code=503,
        detail="Authorization service unavailable",
        headers={"Retry-After": "1"},
    )


@dataclass(frozen=True, slots=True)
class ErrorPolicy:
    """How authorization outcomes become exceptions (HTTP responses)."""

    not_visible: Callable[[Request, ScopeNotVisibleError], Exception] = (
        default_not_visible
    )
    denied: Callable[[Request, PermissionDeniedError], Exception] = default_denied
    unauthenticated: Callable[[Request], Exception] = default_unauthenticated
    unavailable: Callable[[Request, StoreUnavailableError], Exception] = (
        default_unavailable
    )


@dataclass(frozen=True, slots=True)
class DecisionEvent:
    """One authorization decision, delivered to ``AuthzHooks.on_decision``.

    Carries ids and permission names only: never e-mails, tokens or claim values.
    ``roles`` is only filled for ``ALLOWED``: ``NOT_VISIBLE`` reveals nothing about the
    scope and ``DENIED`` is raised before a context exists.
    """

    kind: DecisionKind
    principal_id: str
    scope: ScopeRef
    permission: str
    roles: frozenset[str] = frozenset()
    sensitive: bool = False
    duration_ms: float = 0.0
    request_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view."""
        return {
            "kind": self.kind.value,
            "principal_id": self.principal_id,
            "scope_kind": self.scope.kind,
            "scope_id": self.scope.id,
            "permission": self.permission,
            "roles": sorted(self.roles),
            "sensitive": self.sensitive,
            "duration_ms": round(self.duration_ms, 3),
            "request_id": self.request_id,
        }


@dataclass(frozen=True, slots=True)
class AuthzHooks:
    """Optional callbacks."""

    on_decision: Callable[[DecisionEvent], Awaitable[None] | None] | None = None


class Authz:
    """Catalog + store wiring + error policy, held in ``app.state.authz``."""

    def __init__(
        self,
        *,
        catalog: PermissionCatalog,
        store: AssignmentStore | None,
        store_factory: StoreFactory | None,
        group_roles: Mapping[str, str] | None,
        group_scope_kind: str,
        error_policy: ErrorPolicy,
        hooks: AuthzHooks,
    ) -> None:
        self.catalog = catalog
        self.error_policy = error_policy
        self.hooks = hooks
        self._store = store
        self._store_factory = store_factory
        self._group_roles = dict(group_roles) if group_roles else None
        self._group_scope_kind = group_scope_kind
        self._closed = False

    @classmethod
    def build(
        cls,
        *,
        catalog: PermissionCatalog,
        store: AssignmentStore | None = None,
        store_factory: StoreFactory | None = None,
        group_roles: Mapping[str, str] | None = None,
        group_scope_kind: str = GLOBAL_KIND,
        error_policy: ErrorPolicy | None = None,
        hooks: AuthzHooks | None = None,
    ) -> Authz:
        """Validate the combination of sources and build the runtime.

        Exactly one of ``store`` / ``store_factory``; neither is accepted only
        for a pure group-based setup (``group_roles`` given).

        Raises:
            ConfigurationError: Invalid combination or unknown role/scope kind.
        """
        if store is not None and store_factory is not None:
            raise ConfigurationError("give either store or store_factory, not both")
        if store is None and store_factory is None and not group_roles:
            raise ConfigurationError(
                "no source of roles: give store, store_factory or group_roles"
            )
        if group_roles:
            known = catalog.roles()
            unknown = sorted(set(group_roles.values()) - known)
            if unknown:
                raise ConfigurationError(f"group_roles use unknown roles: {unknown}")
            catalog.scope_kind(group_scope_kind)
        return cls(
            catalog=catalog,
            store=store,
            store_factory=store_factory,
            group_roles=group_roles,
            group_scope_kind=group_scope_kind,
            error_policy=error_policy or ErrorPolicy(),
            hooks=hooks or AuthzHooks(),
        )

    async def authorizer_for(self, request: Request) -> Authorizer:
        """Build an :class:`Authorizer` for ``request`` (calls the factory once)."""
        resolvers: list[RoleResolver] = []
        if self._store_factory is not None:
            store = self._store_factory(request)
            if inspect.isawaitable(store):
                store = await store
            resolvers.append(AssignmentRoleResolver(store))
        elif self._store is not None:
            resolvers.append(AssignmentRoleResolver(self._store))
        if self._group_roles:
            resolvers.append(
                GroupRoleResolver(self._group_roles, scope_kind=self._group_scope_kind)
            )
        return Authorizer(self.catalog, resolvers)

    @classmethod
    def of(cls, request: Request) -> Authz:
        """Return the instance installed on ``request.app``.

        Raises:
            ConfigurationError: Not installed on this app (mounted sub-apps have
                their own ``app.state``: install on each, or pass ``authz=``).
        """
        authz = getattr(request.app.state, "authz", None)
        if not isinstance(authz, Authz):
            raise ConfigurationError("authz not installed on this app")
        return authz

    def install(
        self, app: Starlette, *, allow_disabled_for_development: bool = False
    ) -> None:
        """Attach to ``app``: ``app.state.authz``, route validation and shutdown.

        Route validation runs at lifespan startup. Apps exercised without the
        lifespan (a ``TestClient`` not used as a context manager) should call
        :meth:`validate_routes` themselves, e.g. in an architecture test.

        Raises:
            ConfigurationError: ``AUTH_MIDDLEWARE_DISABLED`` is set and
                ``allow_disabled_for_development`` is not.
        """
        if settings.AUTH_MIDDLEWARE_DISABLED:
            if not allow_disabled_for_development:
                raise ConfigurationError(
                    "AUTH_MIDDLEWARE_DISABLED is set: refusing to install "
                    "authorization (pass allow_disabled_for_development=True)"
                )
            logger.warning(
                "authz installed with AUTH_MIDDLEWARE_DISABLED; guard still enforces"
            )
        app.state.authz = self
        previous = app.router.lifespan_context

        @asynccontextmanager
        async def lifespan(a: Any) -> AsyncIterator[Any]:
            self.validate_routes(app)
            async with previous(a) as state:
                try:
                    yield state
                finally:
                    await self.aclose()

        app.router.lifespan_context = lifespan

    def validate_routes(self, app: Starlette) -> None:
        """Check every guarded route against the catalog.

        Raises:
            UnknownPermissionError: A guard uses a permission not in the catalog.
            ScopeKindMismatchError: A guard's scope kind differs from the permission's.
            ConfigurationError: A path-based scope uses a parameter the route lacks.
        """
        from auth_middleware.authz.errors import ScopeKindMismatchError

        for route_path, param_names, call in _iter_guards(app):
            permission = getattr(call, PERMISSION_ATTR)
            spec = self.catalog.spec(permission)
            source = getattr(call, SCOPE_ATTR, None)
            kind = getattr(source, "kind", None)
            if kind is not None and kind != spec.scope_kind:
                raise ScopeKindMismatchError(
                    f"{route_path}: permission {permission} belongs to scope kind "
                    f"{spec.scope_kind}, guard uses {kind}"
                )
            param = getattr(source, "param", None)
            if param is not None and param not in param_names:
                raise ConfigurationError(
                    f"{route_path}: scope path parameter {param!r} not in the route"
                )

    async def aclose(self) -> None:
        """Close the injected store if it exposes ``aclose()``. Idempotent."""
        if self._closed:
            return
        self._closed = True
        closer = getattr(self._store, "aclose", None)
        if closer is not None:
            result = closer()
            if inspect.isawaitable(result):
                await result


def _iter_guards(app: Any, prefix: str = "") -> Any:
    """Yield ``(path, path_param_names, dependency_callable)`` for guarded routes."""
    from fastapi.routing import APIRoute
    from starlette.routing import Mount

    for route in getattr(app, "routes", []):
        if isinstance(route, APIRoute):
            names = set(route.param_convertors)
            stack = [route.dependant]
            while stack:
                dep = stack.pop()
                stack.extend(dep.dependencies)
                if dep.call is not None and hasattr(dep.call, PERMISSION_ATTR):
                    yield prefix + route.path, names, dep.call
        elif isinstance(route, Mount) and route.app is not None:
            yield from _iter_guards(route.app, prefix + route.path)
