"""The authorizer: generic version of a "membership -> role -> permission" check.

With a policy decision point (ABAC) configured, the 0.7.0 phase runs unchanged and
the policies then refine it (see :mod:`auth_middleware.authz.abac.pdp`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from loguru import logger

from auth_middleware.authz.catalog import PermissionCatalog
from auth_middleware.authz.errors import (
    ConfigurationError,
    PermissionDeniedError,
    ResourceNotFoundError,
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

if TYPE_CHECKING:
    from starlette.requests import Request

    from auth_middleware.authz.abac.attributes import ResourceContext
    from auth_middleware.authz.abac.pdp import (
        AbacOutcome,
        Explanation,
        PolicyDecisionPoint,
    )


@dataclass(slots=True)
class _Evaluation:
    kind: DecisionKind
    context: AuthzContext | None = None
    outcome: AbacOutcome | None = None
    roles: frozenset[str] = frozenset()
    rbac_granted: bool = False
    visible: bool = False
    reason: str = ""


class Authorizer:
    """Decides whether a principal holds a permission in a scope.

    Resolvers run **sequentially in declaration order**, never concurrently:
    stores may share one database session, which is not safe for concurrent use.
    """

    def __init__(
        self,
        catalog: PermissionCatalog,
        resolvers: Sequence[RoleResolver],
        *,
        pdp: PolicyDecisionPoint | None = None,
    ) -> None:
        """
        Args:
            catalog: The permission catalog.
            resolvers: Role resolvers, consulted in order.
            pdp: Optional ABAC decision point. ``None``: exactly the 0.7.0 behaviour.
        """
        self._catalog = catalog
        self._resolvers = tuple(resolvers)
        self._pdp = pdp

    async def _resolve(
        self, principal: Principal, scope: ScopeRef
    ) -> tuple[bool, set[str], dict[str, Any]]:
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
        return found, roles, attributes

    def _granted(self, roles: set[str]) -> frozenset[str]:
        known = self._catalog.roles()
        if not roles <= known:
            # A stored role that left the catalog grants nothing (deny by default)
            # instead of turning every request of that principal into a 500.
            logger.warning(
                "assignment with a role missing from the catalog: {}",
                sorted(roles - known),
            )
            roles &= known
        return frozenset().union(*(self._catalog.permissions_for(r) for r in roles))

    async def _evaluate(
        self,
        principal: Principal,
        permission: str,
        scope: ScopeRef,
        resource: ResourceContext | None,
        request: Request | None,
        *,
        explain: bool = False,
        reveal: bool = False,
    ) -> _Evaluation:
        permission = str(permission)
        spec = self._catalog.spec(permission)
        if spec.scope_kind != scope.kind:
            raise ScopeKindMismatchError(
                f"permission {permission} belongs to scope kind {spec.scope_kind}, "
                f"not {scope.kind}"
            )
        found, roles, attributes = await self._resolve(principal, scope)
        if not found:
            hidden = self._catalog.scope_kind(scope.kind).hide_existence
            return _Evaluation(
                DecisionKind.NOT_VISIBLE if hidden else DecisionKind.DENIED,
                reason="no assignment",
            )
        granted = self._granted(roles)
        rbac = permission in granted
        if self._pdp is None:
            if not rbac:
                return _Evaluation(
                    DecisionKind.DENIED,
                    roles=frozenset(roles),
                    visible=True,
                    reason="role does not grant it",
                )
            ctx = AuthzContext(principal, scope, frozenset(roles), granted, attributes)
            return _Evaluation(
                DecisionKind.ALLOWED,
                ctx,
                roles=frozenset(roles),
                rbac_granted=True,
                visible=True,
                reason="role grants it",
            )
        return await self._with_policies(
            principal,
            permission,
            scope,
            resource,
            request,
            roles,
            granted,
            attributes,
            rbac,
            explain,
            reveal,
        )

    async def _with_policies(
        self,
        principal: Principal,
        permission: str,
        scope: ScopeRef,
        resource: ResourceContext | None,
        request: Request | None,
        roles: set[str],
        granted: frozenset[str],
        attributes: dict[str, Any],
        rbac: bool,
        explain: bool,
        reveal: bool,
    ) -> _Evaluation:
        from auth_middleware.authz.abac.attributes import AttributeRequest

        pdp = self._pdp
        if pdp is None:  # pragma: no cover - the caller checked it
            raise ConfigurationError("no policy decision point configured")
        frozen = frozenset(roles)

        def result(
            kind: DecisionKind,
            reason: str,
            outcome: AbacOutcome | None = None,
            context: AuthzContext | None = None,
        ) -> _Evaluation:
            return _Evaluation(kind, context, outcome, frozen, rbac, True, reason)

        if pdp.mode == "restrict" and not rbac and not explain:
            return result(DecisionKind.DENIED, "role does not grant it")
        request_ctx = AttributeRequest(
            principal, permission, scope, frozen, attributes, resource, request
        )
        try:
            outcome = await pdp.evaluate(request_ctx, explain=explain, reveal=reveal)
        except ResourceNotFoundError:
            return result(DecisionKind.NOT_VISIBLE, "resource not found")
        if outcome.denied:
            kind = DecisionKind.NOT_VISIBLE if outcome.hidden else DecisionKind.DENIED
            return result(kind, outcome.reason or "", outcome)
        if not rbac and not (pdp.mode == "grant" and outcome.permitted):
            return result(DecisionKind.DENIED, "role does not grant it", outcome)
        ctx = AuthzContext(
            principal,
            scope,
            frozen,
            granted | {permission},
            attributes,
            outcome.policy_ids,
            outcome.shadow_policy_ids,
        )
        reason = "role grants it" if rbac else (outcome.reason or "permit")
        return result(DecisionKind.ALLOWED, reason, outcome, ctx)

    async def authorize(
        self,
        principal: Principal,
        permission: str,
        scope: ScopeRef,
        *,
        resource: ResourceContext | None = None,
        request: Request | None = None,
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
        6. With ABAC configured: evaluate the applicable policies (deny-overrides;
           ``hide`` turns a denial into ``ScopeNotVisibleError``).
        7. Return the :class:`AuthzContext`.

        Args:
            principal: Who acts.
            permission: Catalog permission.
            scope: Where.
            resource: The resource (ABAC only).
            request: The request (ABAC providers: headers, ip, claims).

        Raises:
            UnknownPermissionError: Programming error.
            ScopeKindMismatchError: Programming error.
            ScopeNotVisibleError: Principal has no active assignment in scope, the
                resource does not exist, or a ``hide`` policy denied.
            PermissionDeniedError: Principal lacks the permission.
            StoreUnavailableError: A policy source or attribute provider failed.
        """
        ev = await self._evaluate(principal, str(permission), scope, resource, request)
        if ev.kind is DecisionKind.ALLOWED:
            if ev.context is None:  # pragma: no cover - ALLOWED always has one
                raise ConfigurationError("allowed decision without a context")
            return ev.context
        error: ScopeNotVisibleError | PermissionDeniedError
        if ev.kind is DecisionKind.NOT_VISIBLE:
            error = ScopeNotVisibleError(scope)
        else:
            error = PermissionDeniedError(str(permission), scope)
        error.abac = ev.outcome
        raise error

    async def check(
        self,
        principal: Principal,
        permission: str,
        scope: ScopeRef,
        *,
        resource: ResourceContext | None = None,
        request: Request | None = None,
    ) -> DecisionKind:
        """Return the decision kind without raising for the three outcomes."""
        ev = await self._evaluate(principal, str(permission), scope, resource, request)
        return ev.kind

    async def explain(
        self,
        principal: Principal,
        permission: str,
        scope: ScopeRef,
        *,
        resource: ResourceContext | None = None,
        request: Request | None = None,
        reveal: bool = False,
    ) -> Explanation:
        """Run the decision and report why, policy by policy (for logs and tools).

        Every policy is evaluated (no short-circuit). Attribute values are left
        out unless ``reveal``; absent attribute *names* are always listed.
        Never put the result in an HTTP response.
        """
        from auth_middleware.authz.abac.pdp import Explanation

        ev = await self._evaluate(
            principal,
            str(permission),
            scope,
            resource,
            request,
            explain=True,
            reveal=reveal,
        )
        return Explanation(
            ev.kind, ev.rbac_granted, ev.visible, ev.roles, ev.outcome, ev.reason
        )
