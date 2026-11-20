"""AUTHZ-027: policy decision point and Authorizer integration."""

from __future__ import annotations

import itertools
import random

import pytest

from auth_middleware.authz import (
    AssignmentRoleResolver,
    Authorizer,
    DecisionKind,
    NewAssignment,
    PermissionDeniedError,
    Principal,
    ScopeNotVisibleError,
    ScopeRef,
    StoreUnavailableError,
)
from auth_middleware.authz.abac.attributes import (
    AttributeResolver,
    ResourceContext,
    ResourceRef,
)
from auth_middleware.authz.abac.pdp import PolicyDecisionPoint
from auth_middleware.authz.abac.types import (
    Effect,
    EntityRef,
    NewPolicy,
    Policy,
    PolicyScope,
    PolicyStatus,
)
from auth_middleware.authz.errors import ConfigurationError
from auth_middleware.authz.stores.memory import (
    InMemoryAssignmentStore,
    InMemoryAttributeStore,
    InMemoryPolicyStore,
)

S1 = ScopeRef("studio", "s1")
CLEARANCE = {"attr": "subject.attrs.clearance"}
COND = {"eq": [CLEARANCE, 1]}


def pol(pid="p", effect=Effect.DENY, perms=("design.*",), cond=COND, scope=None, **kw):
    return NewPolicy(pid, effect, perms, scope or PolicyScope("studio"), cond, **kw)


class World:
    def __init__(
        self, catalog, mode="restrict", member=True, role="EDI", clearance=None
    ):
        self.assignments = InMemoryAssignmentStore()
        self.policies = InMemoryPolicyStore()
        self.attributes = InMemoryAttributeStore()
        self.catalog = catalog
        self.mode = mode
        self.member, self.role, self.clearance = member, role, clearance

    async def build(self, *policies, resolver=None, source=None):
        if self.member:
            await self.assignments.assign(NewAssignment("u1", S1, self.role))
        if self.clearance is not None:
            await self.attributes.put_attributes(
                EntityRef.principal("u1"),
                {"clearance": self.clearance},
                expected_revision=None,
            )
        for p in policies:
            await self.policies.create(p)
        pdp = PolicyDecisionPoint(
            source or self.policies,
            resolver or AttributeResolver.default(attributes=self.attributes),
            mode=self.mode,
        )
        return Authorizer(
            self.catalog, [AssignmentRoleResolver(self.assignments)], pdp=pdp
        )


PRINCIPAL = Principal("u1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "member,rbac,effect,clearance,mode",
    list(
        itertools.product(
            [True, False],
            [True, False],
            [Effect.DENY, Effect.REQUIRE, Effect.PERMIT],
            [1, 2, None],  # TRUE, FALSE, INDETERMINATE of `clearance == 1`
            ["restrict", "grant"],
        )
    ),
)
async def test_decision_table(catalog, member, rbac, effect, clearance, mode):
    permission = "design.write" if rbac else "design.delete"  # EDI lacks delete
    w = World(catalog, mode=mode, member=member, clearance=clearance)
    authorizer = await w.build(pol(effect=effect, perms=("design.*",)))
    kind = await authorizer.check(PRINCIPAL, permission, S1)

    tri = {1: "T", 2: "F", None: "I"}[clearance]
    if not member:
        expected = DecisionKind.NOT_VISIBLE
    else:
        denial = (effect is Effect.DENY and tri != "F") or (
            effect is Effect.REQUIRE and tri != "T"
        )
        permit = effect is Effect.PERMIT and tri == "T" and mode == "grant"
        if denial:
            expected = DecisionKind.DENIED
        elif rbac or permit:
            expected = DecisionKind.ALLOWED
        else:
            expected = DecisionKind.DENIED
    assert kind is expected


@pytest.mark.asyncio
async def test_without_pdp_behaviour_is_the_0_7_0_one(catalog):
    store = InMemoryAssignmentStore()
    await store.assign(NewAssignment("u1", S1, "EDI"))
    plain = Authorizer(catalog, [AssignmentRoleResolver(store)])
    ctx = await plain.authorize(PRINCIPAL, "design.write", S1)
    assert ctx.policy_ids == () and ctx.shadow_policy_ids == ()
    with pytest.raises(PermissionDeniedError) as exc:
        await plain.authorize(PRINCIPAL, "design.delete", S1)
    assert exc.value.abac is None
    with pytest.raises(ScopeNotVisibleError):
        await plain.authorize(Principal("stranger"), "design.read", S1)


@pytest.mark.asyncio
async def test_deny_carries_the_outcome_and_hide_is_indistinguishable(catalog):
    w = World(catalog, clearance=1)
    a = await w.build(pol("loud"), pol("quiet", hide=True, priority=-1))
    with pytest.raises(ScopeNotVisibleError) as hidden:
        await a.authorize(PRINCIPAL, "design.write", S1)
    assert hidden.value.abac.policy_ids == ("quiet",)  # lower priority number first
    with pytest.raises(ScopeNotVisibleError) as stranger:
        await a.authorize(Principal("stranger"), "design.write", S1)
    assert str(hidden.value) == str(stranger.value)
    await w.policies.set_status("quiet", PolicyStatus.DISABLED, expected_revision=0)
    with pytest.raises(PermissionDeniedError) as loud:
        await a.authorize(PRINCIPAL, "design.write", S1)
    assert loud.value.abac.reason == "deny:loud"


@pytest.mark.asyncio
async def test_indeterminate_reasons(catalog):
    w = World(catalog)
    a = await w.build(pol("d"))
    with pytest.raises(PermissionDeniedError) as exc:
        await a.authorize(PRINCIPAL, "design.write", S1)
    assert exc.value.abac.reason == "indeterminate:d"


@pytest.mark.asyncio
async def test_policies_of_other_scopes_permissions_and_status_do_not_apply(catalog):
    w = World(catalog, clearance=1)
    a = await w.build(
        pol("other-scope", scope=PolicyScope("studio", "s2")),
        pol("other-perm", perms=("billing.*",)),
        pol("off"),
    )
    await w.policies.set_status("off", PolicyStatus.DISABLED, expected_revision=0)
    assert await a.check(PRINCIPAL, "design.write", S1) is DecisionKind.ALLOWED
    assert (
        await a.check(PRINCIPAL, "billing.read", S1) is DecisionKind.DENIED
    )  # EDI lacks it


@pytest.mark.asyncio
async def test_shadow_policy_is_reported_not_enforced(catalog):
    w = World(catalog, clearance=1)
    a = await w.build(pol("shadow", enforce=False))
    ctx = await a.authorize(PRINCIPAL, "design.write", S1)
    assert ctx.shadow_policy_ids == ("shadow",) and ctx.policy_ids == ()
    explanation = await a.explain(PRINCIPAL, "design.write", S1)
    assert explanation.kind is DecisionKind.ALLOWED
    assert explanation.outcome.trace[0].enforced is False


@pytest.mark.asyncio
async def test_grant_mode_permit_grants_what_the_role_does_not(catalog):
    w = World(catalog, mode="grant", clearance=1)
    a = await w.build(pol("grant", Effect.PERMIT, perms=("design.delete",)))
    ctx = await a.authorize(PRINCIPAL, "design.delete", S1)
    assert "design.delete" in ctx.permissions and ctx.policy_ids == ("grant",)
    # a deny still wins over a permit
    await w.policies.create(pol("block", perms=("design.delete",)))
    assert await a.check(PRINCIPAL, "design.delete", S1) is DecisionKind.DENIED
    # ABAC never widens visibility
    assert await a.check(Principal("stranger"), "design.delete", S1) is (
        DecisionKind.NOT_VISIBLE
    )


@pytest.mark.asyncio
async def test_restrict_mode_ignores_permit_policies(catalog):
    w = World(catalog, mode="restrict", clearance=1)
    a = await w.build(pol("grant", Effect.PERMIT, perms=("design.delete",)))
    assert await a.check(PRINCIPAL, "design.delete", S1) is DecisionKind.DENIED


@pytest.mark.asyncio
async def test_resource_loader_and_not_found(catalog):
    owner = {"eq": [{"attr": "resource.attrs.owner_id"}, {"attr": "subject.id"}]}
    not_owner = {"not": owner}
    w = World(catalog)
    a = await w.build(pol("owner-only", perms=("design.delete",), cond=not_owner))
    await w.assignments.revoke("u1", S1, expected_revision=0)
    await w.assignments.assign(NewAssignment("u1", S1, "OWN"))

    def loader(owner_id):
        return lambda request, ref: {"owner_id": owner_id} if owner_id else None

    mine = ResourceContext(ResourceRef("design", "d1"), loader("u1"))
    theirs = ResourceContext(ResourceRef("design", "d2"), loader("u2"))
    gone = ResourceContext(ResourceRef("design", "d3"), loader(None))
    assert (
        await a.check(PRINCIPAL, "design.delete", S1, resource=mine)
        is DecisionKind.ALLOWED
    )
    assert (
        await a.check(PRINCIPAL, "design.delete", S1, resource=theirs)
        is DecisionKind.DENIED
    )
    assert await a.check(PRINCIPAL, "design.delete", S1, resource=gone) is (
        DecisionKind.NOT_VISIBLE
    )
    # the permission the policy does not name never touches the loader
    boom = ResourceContext(ResourceRef("design", "d4"), lambda r, f: 1 / 0)
    assert (
        await a.check(PRINCIPAL, "design.read", S1, resource=boom)
        is DecisionKind.ALLOWED
    )
    with pytest.raises(StoreUnavailableError):
        await a.check(PRINCIPAL, "design.delete", S1, resource=boom)


class _FailingSource:
    async def list_policies(self, scope):
        raise RuntimeError("down")

    async def list_all(self, status=None):
        return []


@pytest.mark.asyncio
async def test_source_failure_is_unavailable_never_allowed(catalog):
    w = World(catalog)
    a = await w.build(source=_FailingSource())
    with pytest.raises(StoreUnavailableError):
        await a.authorize(PRINCIPAL, "design.write", S1)


class _Junk(InMemoryPolicyStore):
    """Returns a policy whose stored condition is not a valid condition."""

    def __init__(self, effect):
        super().__init__()
        self._effect = effect

    async def list_policies(self, scope):
        return [
            Policy(
                "junk",
                self._effect,
                ("design.*",),
                PolicyScope("studio"),
                {"bogus": [1]},
            )
        ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "effect,expected",
    [
        (Effect.DENY, DecisionKind.DENIED),
        (Effect.REQUIRE, DecisionKind.DENIED),
        (Effect.PERMIT, DecisionKind.ALLOWED),
    ],
)
async def test_invalid_stored_condition_fails_closed(catalog, effect, expected):
    w = World(catalog, mode="grant")
    a = await w.build(source=_Junk(effect))
    assert (
        await a.check(PRINCIPAL, "design.write", S1) is expected
    )  # permit grants nothing extra


@pytest.mark.asyncio
async def test_explain_lists_everything_and_redacts_values(catalog):
    w = World(catalog, clearance=1)
    a = await w.build(
        pol("a", priority=0),
        pol("b", Effect.REQUIRE, cond={"gte": [CLEARANCE, 5]}, priority=1),
        pol("c", cond={"eq": [{"attr": "subject.attrs.nope"}, 1]}, priority=2),
    )
    exp = await a.explain(PRINCIPAL, "design.write", S1)
    assert exp.kind is DecisionKind.DENIED
    ids = [t.policy_id for t in exp.outcome.trace]
    assert ids == ["a", "b", "c"]  # no short circuit while explaining
    assert exp.outcome.trace[2].absent == ("subject.attrs.nope",)
    assert all(t.values is None for t in exp.outcome.trace)
    revealed = await a.explain(PRINCIPAL, "design.write", S1, reveal=True)
    assert revealed.outcome.trace[0].values == {"subject.attrs.clearance": 1}
    text = exp.render()
    assert "denied" in text and "absent=" in text


@pytest.mark.asyncio
async def test_enforcing_path_short_circuits(catalog):
    w = World(catalog, clearance=1)
    a = await w.build(pol("first", priority=0), pol("second", priority=1))
    with pytest.raises(PermissionDeniedError) as exc:
        await a.authorize(PRINCIPAL, "design.write", S1)
    assert exc.value.abac.policy_ids == ("first",)
    assert exc.value.abac.trace == ()  # nothing traced when not explaining


def test_invalid_mode():
    with pytest.raises(ConfigurationError):
        PolicyDecisionPoint(InMemoryPolicyStore(), AttributeResolver([]), mode="x")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_restrict_never_turns_a_denial_into_an_allow(catalog):
    """Property: in restrict mode ABAC can only narrow what RBAC granted."""
    rng = random.Random(7)
    conds = [
        COND,
        {"not": COND},
        {"eq": [{"attr": "subject.attrs.nope"}, 1]},
        {"exists": CLEARANCE},
        {"gt": [CLEARANCE, 0]},
    ]
    for _ in range(40):
        w = World(catalog, clearance=rng.choice([1, 2, None]))
        policies = [
            pol(
                f"p{i}",
                rng.choice(list(Effect)),
                perms=("*",) if False else ("design.*",),
                cond=rng.choice(conds),
                enforce=rng.random() > 0.3,
                hide=False,
            )
            for i in range(rng.randint(1, 4))
        ]
        a = await w.build(*policies)
        plain = Authorizer(catalog, [AssignmentRoleResolver(w.assignments)])
        for perm in ("design.read", "design.write", "design.delete"):
            with_abac = await a.check(PRINCIPAL, perm, S1)
            without = await plain.check(PRINCIPAL, perm, S1)
            if without is not DecisionKind.ALLOWED:
                assert with_abac is not DecisionKind.ALLOWED
