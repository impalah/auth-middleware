"""Errors of the scoped-permissions subsystem."""

from __future__ import annotations

from auth_middleware.authz.types import ScopeRef


class AuthzError(Exception):
    """Base class of every authz error."""


class ScopeNotVisibleError(AuthzError):
    """No active assignment in the scope, or the scope does not exist.

    Both cases are deliberately indistinguishable (default HTTP 404).
    """

    def __init__(self, scope: ScopeRef) -> None:
        super().__init__(f"scope not visible: {scope.kind}")
        self.scope = scope


class PermissionDeniedError(AuthzError):
    """The principal is known in the scope but lacks ``required``."""

    def __init__(self, required: str, scope: ScopeRef) -> None:
        super().__init__(f"permission denied: {required}")
        self.required = required
        self.scope = scope


class UnknownPermissionError(AuthzError):
    """A permission not present in the catalog (programming mistake)."""


class CatalogError(AuthzError):
    """Invalid or inconsistent permission catalog (configuration mistake)."""


class ScopeKindMismatchError(AuthzError):
    """A permission checked against a scope of another kind (programming mistake)."""


class ConfigurationError(AuthzError):
    """Invalid wiring of the authz runtime (configuration mistake)."""


class RevisionConflictError(AuthzError):
    """Optimistic-concurrency failure on an assignment write."""


class InvalidScopeError(AuthzError):
    """A scope id taken from a request is not a valid ``ScopeRef`` (too long, ``*``...).

    The guard answers it exactly like an unknown scope (not visible).
    """

    def __init__(self, kind: str) -> None:
        super().__init__(f"invalid scope id for kind {kind}")
        self.kind = kind


class StoreUnavailableError(AuthzError):
    """The backing store is throttling or unreachable (the guard may answer 503)."""


class UnknownRoleError(AuthzError, ValueError):
    """A role not present in the catalog."""
