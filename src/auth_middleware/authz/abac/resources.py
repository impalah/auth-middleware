"""Where the resource of a request comes from (the ABAC twin of ``ScopeSource``)."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Protocol

from starlette.requests import Request

from auth_middleware.authz.abac.attributes import ResourceLoader, ResourceRef
from auth_middleware.authz.errors import ConfigurationError, InvalidScopeError


def _ref_or_invalid(kind: str, value: str) -> ResourceRef:
    """An invalid id from a request is "not visible", never a server error."""
    try:
        return ResourceRef(kind, value)
    except ValueError:
        raise InvalidScopeError(kind) from None


class ResourceSource(Protocol):
    """Resolves the :class:`ResourceRef` a request is about."""

    kind: str
    loader: ResourceLoader | None

    async def resolve(self, request: Request) -> ResourceRef:
        """Return the resource of ``request``."""
        ...


class ResourceFromPath:
    """Resource id read from a path parameter.

    Args:
        kind: Resource kind (``design``).
        param: Path parameter holding the id.
        loader: ``loader(request, ref) -> attributes | None`` reading the
            resource's attributes from the application's own data.
    """

    def __init__(
        self, kind: str, param: str, loader: ResourceLoader | None = None
    ) -> None:
        self.kind = kind
        self.param = param
        self.loader = loader

    async def resolve(self, request: Request) -> ResourceRef:
        try:
            value = request.path_params[self.param]
        except KeyError:
            raise ConfigurationError(
                f"path parameter {self.param!r} missing in this route"
            ) from None
        return _ref_or_invalid(self.kind, str(value))


class ResourceFromQuery:
    """Resource id read from a query parameter (missing: not visible)."""

    def __init__(
        self, kind: str, param: str, loader: ResourceLoader | None = None
    ) -> None:
        self.kind = kind
        self.param = param
        self.loader = loader

    async def resolve(self, request: Request) -> ResourceRef:
        return _ref_or_invalid(self.kind, request.query_params.get(self.param, ""))


class ResourceFromCallable:
    """Resource id computed by a (sync or async) function of the request.

    Use it when the id lives in the body: read the body yourself (and keep it
    available for the handler), the library never consumes it.
    """

    def __init__(
        self,
        kind: str,
        fn: Callable[[Request], str | Awaitable[str]],
        loader: ResourceLoader | None = None,
    ) -> None:
        self.kind = kind
        self._fn = fn
        self.loader = loader

    async def resolve(self, request: Request) -> ResourceRef:
        value = self._fn(request)
        if inspect.isawaitable(value):
            value = await value
        return _ref_or_invalid(self.kind, str(value))
