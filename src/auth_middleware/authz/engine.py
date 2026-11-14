"""The authorizer: generic version of a "membership -> role -> permission" check."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from loguru import logger

from auth_middleware.authz.catalog import PermissionCatalog
from auth_middleware.authz.errors import (
    PermissionDeniedError,
    ScopeKindMismatchError,
    ScopeNotVisibleError,
)
from auth_middleware.authz.resolvers import RoleResolver
from auth_middleware.authz.types import (
    AuthzContext,
    DecisionKind,
    Principal,
    ScopeRef,
)


class Authorizer:
    """Decides whether a principal holds a permission in a scope.

    Resolvers run **sequentially in declaration order**, never concurrently:
    stores may share one database session, which is not safe for concurrent use.
    """

    def __init__(
        self, catalog: PermissionCatalog, resolvers: Sequence[RoleResolver]
    ) -> None:
        """
        Args:
            catalog: The permission catalog.
            resolvers: Role resolvers, consulted in order.
        """
        self._catalog = catalog
        self._resolvers = tuple(resolvers)

    async def authorize(
        self, principal: Principal, permission: str, scope: ScopeRef
    ) -> AuthzContext:
        """Authorize or raise.

        Algorithm:

        1. ``catalog.spec(permission)`` (unknown -> ``UnknownPermissionError``).
        2. The permission's scope kind must equal ``scope.kind``
           (else ``ScopeKindMismatchError``).
        3. Ask every resolver; union the roles and merge attributes (later
           resolvers win on key clashes).
        4. No result: ``ScopeNotVisibleError`` if the scope kind hides
           existence, else ``PermissionDeniedError``.
        5. Permission not in the union of the roles' permissions ->
           ``PermissionDeniedError``.
        6. Return the :class:`AuthzContext`.

        Raises:
            UnknownPermissionError: Programming error.
            ScopeKindMismatchError: Programming error.
            ScopeNotVisibleError: Principal has no active assignment in scope.
            PermissionDeniedError: Principal lacks the permission.
        """
        permission = str(permission)
        spec = self._catalog.spec(permission)
        if spec.scope_kind != scope.kind:
            raise ScopeKindMismatchError(
                f"permission {permission} belongs to scope kind {spec.scope_kind}, "
                f"not {scope.kind}"
            )
        roles: set[str] = set()
        attributes: dict[str, Any] = {}
        found = False
        for resolver in self._resolvers:
            result = await resolver.resolve(principal, scope)
            if result is None:
                continue
            found = True
            roles |= result.roles
            attributes.update(result.attributes)
        if not found:
            if self._catalog.scope_kind(scope.kind).hide_existence:
                raise ScopeNotVisibleError(scope)
            raise PermissionDeniedError(permission, scope)
        known = self._catalog.roles()
        if not roles <= known:
            # A stored role that left the catalog grants nothing (deny by default)
            # instead of turning every request of that principal into a 500.
            logger.warning(
                "assignment with a role missing from the catalog: {}",
                sorted(roles - known),
            )
            roles &= known
        granted: frozenset[str] = frozenset().union(
            *(self._catalog.permissions_for(r) for r in roles)
        )
        if permission not in granted:
            raise PermissionDeniedError(permission, scope)
        return AuthzContext(principal, scope, frozenset(roles), granted, attributes)

    async def check(
        self, principal: Principal, permission: str, scope: ScopeRef
    ) -> DecisionKind:
        """Return the decision kind without raising for the three outcomes."""
        try:
            await self.authorize(principal, permission, scope)
        except ScopeNotVisibleError:
            return DecisionKind.NOT_VISIBLE
        except PermissionDeniedError:
            return DecisionKind.DENIED
        return DecisionKind.ALLOWED
