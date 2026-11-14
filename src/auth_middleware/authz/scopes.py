"""Where the scope of a request comes from."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Protocol

from starlette.requests import Request

from auth_middleware.authz.errors import ConfigurationError, InvalidScopeError
from auth_middleware.authz.types import GLOBAL_KIND, ScopeRef


def _scope_or_invalid(kind: str, value: str) -> ScopeRef:
    """Build a ScopeRef from request data; invalid ids are not a server error."""
    try:
        return ScopeRef(kind, value)
    except ValueError:
        raise InvalidScopeError(kind) from None


class ScopeSource(Protocol):
    """Resolves the :class:`ScopeRef` a request is about."""

    #: Scope kind produced, used to validate guards against the catalog at startup.
    kind: str

    async def resolve(self, request: Request) -> ScopeRef:
        """Return the scope of ``request``."""
        ...


class GlobalScope:
    """Platform-wide scope."""

    kind = GLOBAL_KIND

    async def resolve(self, request: Request) -> ScopeRef:
        return ScopeRef.GLOBAL


class ScopeFromPath:
    """Scope id read from a path parameter."""

    def __init__(self, kind: str, param: str) -> None:
        """
        Args:
            kind: Scope kind.
            param: Name of the path parameter holding the scope id.
        """
        self.kind = kind
        self.param = param

    async def resolve(self, request: Request) -> ScopeRef:
        try:
            value = request.path_params[self.param]
        except KeyError:
            raise ConfigurationError(
                f"path parameter {self.param!r} missing in this route"
            ) from None
        return _scope_or_invalid(self.kind, str(value))


class ScopeFromCallable:
    """Scope id computed by a (sync or async) function of the request."""

    def __init__(
        self, kind: str, fn: Callable[[Request], str | Awaitable[str]]
    ) -> None:
        """
        Args:
            kind: Scope kind.
            fn: Function returning the scope id.
        """
        self.kind = kind
        self._fn = fn

    async def resolve(self, request: Request) -> ScopeRef:
        value = self._fn(request)
        if inspect.isawaitable(value):
            value = await value
        return _scope_or_invalid(self.kind, str(value))
