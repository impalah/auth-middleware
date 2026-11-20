"""The policy decision point: evaluates the applicable policies of one decision.

Deny-overrides over the enforced policies, with fail-closed three-valued logic:

* ``deny``: applies when its condition is TRUE **or INDETERMINATE**.
* ``require``: denies unless its condition is TRUE.
* ``permit`` (``grant`` mode only): grants only when TRUE.

``enforce=False`` policies are evaluated and reported (``shadow_policy_ids``)
but never change the outcome.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from loguru import logger

from auth_middleware.authz.abac.attributes import AttributeRequest, AttributeResolver
from auth_middleware.authz.abac.conditions import (
    ABSENT,
    Condition,
    Tri,
    condition_paths,
    evaluate,
    parse_condition,
)
from auth_middleware.authz.abac.types import Effect, Policy, PolicyStatus
from auth_middleware.authz.abac.validation import policy_matches_permission
from auth_middleware.authz.errors import (
    AuthzError,
    ConditionError,
    ConfigurationError,
    StoreUnavailableError,
)
from auth_middleware.authz.ports import PolicyStore
from auth_middleware.authz.types import DecisionKind

Mode = Literal["restrict", "grant"]


@dataclass(frozen=True, slots=True)
class PolicyTrace:
    """What one policy did in a decision (for ``explain``; values are opt-in)."""

    policy_id: str
    effect: Effect
    enforced: bool
    result: Tri
    decisive: bool
    reason: str
    absent: tuple[str, ...] = ()
    values: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class AbacOutcome:
    """The result of the policy phase of one decision."""

    denied: bool = False
    hidden: bool = False
    permitted: bool = False
    policy_ids: tuple[str, ...] = ()
    shadow_policy_ids: tuple[str, ...] = ()
    reason: str | None = None
    trace: tuple[PolicyTrace, ...] = ()


@dataclass(frozen=True, slots=True)
class Explanation:
    """Why a decision came out as it did. For logs and tools, never for clients."""

    kind: DecisionKind
    rbac_granted: bool
    visible: bool
    roles: frozenset[str]
    outcome: AbacOutcome | None
    reason: str

    def render(self) -> str:
        """Human-readable multi-line text."""
        lines = [
            f"decision: {self.kind.value} ({self.reason})",
            f"visible: {self.visible}  rbac_granted: {self.rbac_granted}  "
            f"roles: {sorted(self.roles)}",
        ]
        for t in self.outcome.trace if self.outcome else ():
            mark = "*" if t.decisive else " "
            shadow = "" if t.enforced else " [shadow]"
            lines.append(
                f" {mark} {t.policy_id} {t.effect.value} -> {t.result.value}"
                f"{shadow} {t.reason}"
                + (f" absent={list(t.absent)}" if t.absent else "")
            )
        return "\n".join(lines)


@dataclass(slots=True)
class _Tally:
    """Running result of the policies of one decision."""

    denial: tuple[Policy, str] | None = None
    permits: list[str] = field(default_factory=list)
    shadow: list[str] = field(default_factory=list)
    trace: list[PolicyTrace] = field(default_factory=list)


def _denies(effect: Effect, result: Tri) -> bool:
    if effect is Effect.DENY:
        return result is not Tri.FALSE
    if effect is Effect.REQUIRE:
        return result is not Tri.TRUE
    return False


def _reason(effect: Effect, result: Tri, policy_id: str) -> str:
    if result is Tri.INDETERMINATE:
        return f"indeterminate:{policy_id}"
    return f"{effect.value}:{policy_id}"


class PolicyDecisionPoint:
    """Loads, evaluates and combines the policies of a decision."""

    def __init__(
        self,
        policies: PolicyStore,
        resolver: AttributeResolver,
        *,
        mode: Mode = "restrict",
    ) -> None:
        """
        Args:
            policies: Where the policies come from.
            resolver: Where the attributes come from.
            mode: ``restrict`` (policies only narrow) or ``grant`` (``permit``
                policies may grant; experimental).
        """
        if mode not in ("restrict", "grant"):
            raise ConfigurationError(f"unknown ABAC mode: {mode!r}")
        self._policies = policies
        self._resolver = resolver
        self.mode: Mode = mode
        self._warned: set[str] = set()

    async def _load(self, ctx: AttributeRequest, permission: str) -> list[Policy]:
        try:
            found = await self._policies.list_policies(ctx.scope)
            usable = [
                p
                for p in found
                if p.status is PolicyStatus.ACTIVE
                and any(policy_matches_permission(x, permission) for x in p.permissions)
            ]
            return sorted(usable, key=lambda p: (p.priority, p.id))
        except AuthzError:
            raise
        except Exception as exc:
            # A broken source or a poisoned cache entry is an outage, never an allow.
            logger.opt(exception=True).error("policy source failed")
            raise StoreUnavailableError("policy source failed") from exc

    def _parse(self, policy: Policy) -> Condition | None:
        try:
            return parse_condition(policy.condition)
        except ConditionError:
            logger.error(
                "stored policy {} has an invalid condition: it fails closed", policy.id
            )
            return None

    def _skip_permit(self, policy: Policy) -> bool:
        if policy.effect is Effect.PERMIT and self.mode != "grant":
            if policy.id not in self._warned:
                self._warned.add(policy.id)
                logger.warning(
                    "policy {} is a permit but the mode is restrict: ignored", policy.id
                )
            return True
        return False

    async def evaluate(
        self, ctx: AttributeRequest, *, explain: bool = False, reveal: bool = False
    ) -> AbacOutcome:
        """Run the policy phase.

        Args:
            ctx: Principal, permission, scope, resource and request.
            explain: Evaluate every policy and fill the trace.
            reveal: Include attribute values in the trace (never for clients).

        Raises:
            ResourceNotFoundError: The resource loader said it does not exist.
            StoreUnavailableError: A source or provider failed (never an allow).
        """
        try:
            return await self._evaluate(ctx, explain, reveal)
        except AuthzError:
            raise
        except Exception as exc:
            logger.opt(exception=True).error("policy evaluation failed")
            raise StoreUnavailableError("policy evaluation failed") from exc

    async def _evaluate(
        self, ctx: AttributeRequest, explain: bool, reveal: bool
    ) -> AbacOutcome:
        policies = [
            p for p in await self._load(ctx, ctx.permission) if not self._skip_permit(p)
        ]
        parsed = [(p, self._parse(p)) for p in policies]
        needed = frozenset().union(
            *(condition_paths(c) for _, c in parsed if c is not None)
        )
        values = await self._resolver.resolve(ctx, needed) if needed else {}

        tally = _Tally()
        for policy, cond in parsed:
            if tally.denial is not None and policy.enforce and not explain:
                continue
            self._judge(tally, policy, cond, values, explain, reveal)
        return self._outcome(tally)

    def _judge(
        self,
        tally: _Tally,
        policy: Policy,
        cond: Condition | None,
        values: Mapping[str, Any],
        explain: bool,
        reveal: bool,
    ) -> None:
        result = Tri.INDETERMINATE if cond is None else evaluate(cond, values)
        denies = _denies(policy.effect, result)
        reason = _reason(policy.effect, result, policy.id)
        if not policy.enforce:
            if denies:
                tally.shadow.append(policy.id)
        elif denies:
            if tally.denial is None:
                tally.denial = (policy, reason)
        elif policy.effect is Effect.PERMIT and result is Tri.TRUE:
            tally.permits.append(policy.id)
        if explain:
            tally.trace.append(
                self._trace(policy, cond, result, denies, reason, values, reveal)
            )

    @staticmethod
    def _trace(
        policy: Policy,
        cond: Condition | None,
        result: Tri,
        denies: bool,
        reason: str,
        values: Mapping[str, Any],
        reveal: bool,
    ) -> PolicyTrace:
        paths = condition_paths(cond) if cond is not None else frozenset()
        absent = tuple(sorted(p for p in paths if values.get(p, ABSENT) is ABSENT))
        shown = {p: values[p] for p in paths if p in values} if reveal else None
        decisive = policy.enforce and (
            denies or (policy.effect is Effect.PERMIT and result is Tri.TRUE)
        )
        return PolicyTrace(
            policy.id,
            policy.effect,
            policy.enforce,
            result,
            decisive,
            reason,
            absent,
            shown,
        )

    @staticmethod
    def _outcome(tally: _Tally) -> AbacOutcome:
        trace = tuple(tally.trace)
        shadow = tuple(tally.shadow)
        if tally.denial is not None:
            policy, reason = tally.denial
            return AbacOutcome(
                denied=True,
                hidden=policy.hide,
                policy_ids=(policy.id,),
                shadow_policy_ids=shadow,
                reason=reason,
                trace=trace,
            )
        permits = tally.permits
        return AbacOutcome(
            permitted=bool(permits),
            policy_ids=tuple(permits),
            shadow_policy_ids=shadow,
            reason=f"permit:{permits[0]}" if permits else None,
            trace=trace,
        )
