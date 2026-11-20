"""Tests added after a mutation-testing pass over the engine and the decision point.

Each test pins down behaviour a surviving mutant had changed without any test noticing:
the content of ``explain()`` in every branch, the restrict-mode short circuit, the
request reaching the attribute providers, shadow policies after an enforced denial,
the warn-once for ignored ``permit`` policies and the exact trace of a policy.
"""

from __future__ import annotations

import pytest
from loguru import logger
from starlette.requests import Request

from auth_middleware.authz import (
    AssignmentRoleResolver,
    Authorizer,
    DecisionKind,
    NewAssignment,
    Principal,
    ScopeRef,
    StoreUnavailableError,
)
from auth_middleware.authz.abac.attributes import (
    AttributeRequest,
    AttributeResolver,
    ResourceContext,
    ResourceRef,
)
from auth_middleware.authz.abac.pdp import PolicyDecisionPoint
from auth_middleware.authz.abac.types import Effect, NewPolicy, Policy, PolicyScope
from auth_middleware.authz.stores.memory import (
    InMemoryAssignmentStore,
    InMemoryAttributeStore,
    InMemoryPolicyStore,
)

S1 = ScopeRef("studio", "s1")
U1 = Principal("u1", ("g",), "u1@x.org")
OWNER = {"eq": [{"attr": "resource.attrs.owner_id"}, {"attr": "subject.id"}]}
CLEAR = {"attr": "subject.attrs.clearance"}


def pol(pid, effect=Effect.DENY, perms=("design.*",), cond=None, **kw):
    cond = cond or {"eq": [CLEAR, 1]}
    return NewPolicy(pid, effect, perms, PolicyScope("studio"), cond, **kw)


async def build(
    catalog, *policies, mode="restrict", role="EDI", member=True, clearance=1
):
    assignments, store, attrs = (
        InMemoryAssignmentStore(),
        InMemoryPolicyStore(),
        InMemoryAttributeStore(),
    )
    if member:
        await assignments.assign(NewAssignment("u1", S1, role))
    if clearance is not None:
        from auth_middleware.authz.abac.types import EntityRef

        await attrs.put_attributes(
            EntityRef.principal("u1"), {"clearance": clearance}, expected_revision=None
        )
    for p in policies:
        await store.create(p)
    pdp = PolicyDecisionPoint(
        store, AttributeResolver.default(attributes=attrs), mode=mode
    )
    return Authorizer(catalog, [AssignmentRoleResolver(assignments)], pdp=pdp), pdp


def request(method="GET", path="/x"):
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "query_string": b"",
            "client": ("1.2.3.4", 1),
        }
    )


# ------------------------------------------------------------ explain() fields


@pytest.mark.asyncio
async def test_explain_reports_every_branch_exactly(catalog):
    # not a member: nothing is revealed, not even the roles
    a, _ = await build(catalog, member=False)
    e = await a.explain(U1, "design.read", S1)
    assert (e.kind, e.visible, e.rbac_granted, e.roles, e.reason) == (
        DecisionKind.NOT_VISIBLE,
        False,
        False,
        frozenset(),
        "no assignment",
    )

    # member whose role does not grant the permission (EDI has no design.delete)
    a, _ = await build(catalog)
    e = await a.explain(U1, "design.delete", S1)
    assert (e.kind, e.visible, e.rbac_granted, e.roles, e.reason) == (
        DecisionKind.DENIED,
        True,
        False,
        frozenset({"EDI"}),
        "role does not grant it",
    )

    # allowed by the role
    e = await a.explain(U1, "design.read", S1)
    assert (e.kind, e.visible, e.rbac_granted, e.roles, e.reason) == (
        DecisionKind.ALLOWED,
        True,
        True,
        frozenset({"EDI"}),
        "role grants it",
    )

    # denied by a policy
    a, _ = await build(catalog, pol("block"))
    e = await a.explain(U1, "design.read", S1)
    assert (e.kind, e.visible, e.rbac_granted, e.reason) == (
        DecisionKind.DENIED,
        True,
        True,
        "deny:block",
    )


@pytest.mark.asyncio
async def test_plain_authorizer_explain_and_context_fields(catalog):
    assignments = InMemoryAssignmentStore()
    await assignments.assign(NewAssignment("u1", S1, "EDI", {"tag": "x"}))
    plain = Authorizer(catalog, [AssignmentRoleResolver(assignments)])
    ctx = await plain.authorize(U1, "design.read", S1)
    assert ctx.principal == U1 and ctx.scope == S1 and ctx.roles == frozenset({"EDI"})
    assert ctx.permissions == frozenset({"design.read", "design.write"})
    assert ctx.attributes == {"tag": "x"}
    for permission, kind, rbac, reason in (
        ("design.read", DecisionKind.ALLOWED, True, "role grants it"),
        ("design.delete", DecisionKind.DENIED, False, "role does not grant it"),
    ):
        e = await plain.explain(U1, permission, S1)
        assert (e.kind, e.visible, e.rbac_granted, e.roles, e.reason) == (
            kind,
            True,
            rbac,
            frozenset({"EDI"}),
            reason,
        )


@pytest.mark.asyncio
async def test_abac_context_carries_the_decision_data(catalog):
    a, _ = await build(catalog, pol("shadow", enforce=False))
    ctx = await a.authorize(U1, "design.read", S1)
    assert ctx.principal == U1 and ctx.scope == S1
    assert ctx.roles == frozenset({"EDI"}) and "design.read" in ctx.permissions
    assert ctx.shadow_policy_ids == ("shadow",)


# ------------------------------------------------- restrict-mode short circuit


@pytest.mark.asyncio
async def test_restrict_mode_does_not_load_anything_when_the_role_already_denies(
    catalog,
):
    calls = []

    def loader(req, ref):
        calls.append(ref.id)
        return {"owner_id": "u1"}

    a, _ = await build(
        catalog, pol("owner", Effect.REQUIRE, ("design.delete",), OWNER), role="EDI"
    )  # EDI cannot delete: the role denies first
    res = ResourceContext(ResourceRef("design", "d1"), loader)
    assert await a.check(U1, "design.delete", S1, resource=res) is DecisionKind.DENIED
    assert calls == []  # no policy phase, no loader call
    e = await a.explain(
        U1, "design.delete", S1, resource=res
    )  # explaining evaluates anyway
    assert e.kind is DecisionKind.DENIED and calls == ["d1"]


@pytest.mark.asyncio
async def test_grant_mode_always_runs_the_policy_phase(catalog):
    calls = []

    def loader(req, ref):
        calls.append(1)
        return {"owner_id": "u1"}

    grant = pol("g", Effect.PERMIT, ("design.delete",), OWNER)
    a, _ = await build(catalog, grant, mode="grant", role="EDI")
    res = ResourceContext(ResourceRef("design", "d1"), loader)
    assert await a.check(U1, "design.delete", S1, resource=res) is DecisionKind.ALLOWED
    assert calls == [1]


# ------------------------------------------------ the request reaches providers


@pytest.mark.asyncio
async def test_the_request_reaches_the_attribute_providers(catalog):
    only_get = pol("no-delete", cond={"eq": [{"attr": "env.method"}, "DELETE"]})
    a, _ = await build(catalog, only_get)
    assert await a.check(U1, "design.read", S1, request=request("DELETE")) is (
        DecisionKind.DENIED
    )
    assert await a.check(U1, "design.read", S1, request=request("GET")) is (
        DecisionKind.ALLOWED
    )
    # without a request the method is unknown: the deny applies (fail closed)
    assert await a.check(U1, "design.read", S1) is DecisionKind.DENIED


@pytest.mark.asyncio
async def test_the_loader_receives_the_request_and_the_reference(catalog):
    seen = []

    def loader(req, ref):
        seen.append((req, ref))
        return {"owner_id": "u1"}

    a, _ = await build(catalog, pol("o", Effect.REQUIRE, ("design.write",), OWNER))
    req = request()
    ref = ResourceRef("design", "d9")
    await a.check(
        U1, "design.write", S1, resource=ResourceContext(ref, loader), request=req
    )
    assert seen == [(req, ref)]


# ------------------------------------------------------------------- the PDP


def attr_request(permission="design.read"):
    return AttributeRequest(U1, permission, S1, frozenset({"EDI"}), {}, None, None)


@pytest.mark.asyncio
async def test_evaluate_defaults_to_no_trace_and_no_values(catalog):
    a, pdp = await build(catalog, pol("block"))
    out = await pdp.evaluate(attr_request())
    assert out.denied and out.trace == ()
    traced = await pdp.evaluate(attr_request(), explain=True)
    assert traced.trace[0].values is None  # reveal is off by default
    revealed = await pdp.evaluate(attr_request(), explain=True, reveal=True)
    assert revealed.trace[0].values == {"subject.attrs.clearance": 1}


@pytest.mark.asyncio
async def test_shadow_policies_are_still_evaluated_after_an_enforced_denial(catalog):
    a, pdp = await build(
        catalog,
        pol("first", priority=0),
        pol("later-enforced", priority=1),
        pol("later-shadow", priority=2, enforce=False),
    )
    out = await pdp.evaluate(attr_request())
    assert out.denied and out.policy_ids == ("first",)
    assert out.shadow_policy_ids == ("later-shadow",)  # not skipped by the denial


@pytest.mark.asyncio
async def test_trace_entries_are_exact(catalog):
    a, pdp = await build(
        catalog,
        pol("hit", priority=0),  # clearance == 1 -> TRUE -> deny applies, decisive
        pol("miss", priority=1, cond={"eq": [CLEAR, 2]}),  # FALSE
        pol("unknown", priority=2, cond={"eq": [{"attr": "subject.attrs.ghost"}, 1]}),
        pol("shadow", priority=3, enforce=False),  # TRUE but not enforced
        pol("req", Effect.REQUIRE, priority=4, cond={"eq": [CLEAR, 1]}),  # satisfied
    )
    out = await pdp.evaluate(attr_request(), explain=True)
    rows = {t.policy_id: t for t in out.trace}
    assert [t.policy_id for t in out.trace] == [
        "hit",
        "miss",
        "unknown",
        "shadow",
        "req",
    ]
    hit = rows["hit"]
    assert (hit.effect, hit.enforced, hit.result.value, hit.decisive, hit.reason) == (
        Effect.DENY,
        True,
        "true",
        True,
        "deny:hit",
    )
    assert rows["miss"].result.value == "false" and rows["miss"].decisive is False
    assert rows["miss"].reason == "deny:miss"
    unknown = rows["unknown"]
    assert unknown.result.value == "indeterminate" and unknown.decisive is True
    assert unknown.reason == "indeterminate:unknown"
    assert unknown.absent == ("subject.attrs.ghost",)
    shadow = rows["shadow"]
    assert shadow.enforced is False and shadow.decisive is False
    assert shadow.result.value == "true"
    req = rows["req"]
    assert (
        req.result.value == "true"
        and req.decisive is False
        and req.reason == "require:req"
    )
    assert rows["hit"].absent == ()


@pytest.mark.asyncio
async def test_a_permit_that_grants_is_decisive_in_the_trace(catalog):
    a, pdp = await build(catalog, pol("g", Effect.PERMIT, ("design.*",)), mode="grant")
    out = await pdp.evaluate(attr_request(), explain=True)
    assert out.permitted and out.policy_ids == ("g",) and out.reason == "permit:g"
    assert out.trace[0].decisive is True


@pytest.mark.asyncio
async def test_render_is_exact(catalog):
    a, _ = await build(
        catalog,
        pol("hit", priority=0),
        pol("sh", priority=1, enforce=False),
        pol("unk", priority=2, cond={"eq": [{"attr": "subject.attrs.ghost"}, 1]}),
    )
    text = (await a.explain(U1, "design.read", S1)).render()
    assert text == (
        "decision: denied (deny:hit)\n"
        "visible: True  rbac_granted: True  roles: ['EDI']\n"
        " * hit deny -> true deny:hit\n"
        "   sh deny -> true [shadow] deny:sh\n"
        " * unk deny -> indeterminate indeterminate:unk absent=['subject.attrs.ghost']"
    )
    quiet, _ = await build(catalog)
    assert (await quiet.explain(U1, "design.read", S1)).render().splitlines()[0] == (
        "decision: allowed (role grants it)"
    )


# ------------------------------------------------- warnings, errors, fail-closed


@pytest.mark.asyncio
async def test_a_permit_in_restrict_mode_is_ignored_and_warned_about_once(catalog):
    a, pdp = await build(
        catalog, pol("g", Effect.PERMIT, ("design.*",)), mode="restrict"
    )
    captured: list[str] = []
    sink = logger.add(lambda m: captured.append(str(m)), level="WARNING")
    try:
        first = await pdp.evaluate(attr_request(), explain=True)
        await pdp.evaluate(attr_request())
    finally:
        logger.remove(sink)
    assert first.permitted is False and first.policy_ids == () and first.trace == ()
    warnings = [m for m in captured if "is a permit but the mode is restrict" in m]
    assert len(warnings) == 1 and "g" in warnings[0]


@pytest.mark.asyncio
async def test_an_invalid_stored_condition_is_logged_with_its_id_and_traced_safely(
    catalog,
):
    class Junk(InMemoryPolicyStore):
        async def list_policies(self, scope):
            return [
                Policy(
                    "junk-1",
                    Effect.DENY,
                    ("design.*",),
                    PolicyScope("studio"),
                    {"bogus": [1]},
                )
            ]

    pdp = PolicyDecisionPoint(Junk(), AttributeResolver.default())
    captured: list[str] = []
    sink = logger.add(lambda m: captured.append(str(m)), level="ERROR")
    try:
        out = await pdp.evaluate(attr_request(), explain=True)
    finally:
        logger.remove(sink)
    assert out.denied and out.reason == "indeterminate:junk-1"
    row = out.trace[0]
    assert row.absent == () and row.decisive is True  # no condition, nothing to list
    assert any("junk-1" in m and "fails closed" in m for m in captured)


@pytest.mark.asyncio
async def test_failure_messages_are_exact(catalog):
    class Down:
        async def list_policies(self, scope):
            raise RuntimeError("x")

    with pytest.raises(StoreUnavailableError) as exc:
        await PolicyDecisionPoint(Down(), AttributeResolver([])).evaluate(
            attr_request()
        )
    assert str(exc.value) == "policy source failed"

    class Weird(InMemoryPolicyStore):
        async def list_policies(self, scope):
            return [
                Policy(
                    "p",
                    Effect.DENY,
                    ("design.*",),
                    PolicyScope("studio"),
                    {"eq": [CLEAR, 1]},
                )
            ]

    class BadResolver:
        async def resolve(self, ctx, needed):
            raise KeyError("boom")

    with pytest.raises(StoreUnavailableError) as exc2:
        await PolicyDecisionPoint(Weird(), BadResolver()).evaluate(attr_request())  # type: ignore[arg-type]
    assert str(exc2.value) == "policy evaluation failed"


# ------------------------------------------------ second pass over the engine


@pytest.mark.asyncio
async def test_scope_kind_mismatch_message_and_denial_exception_fields(catalog):
    from auth_middleware.authz import PermissionDeniedError, ScopeKindMismatchError

    a, _ = await build(catalog)
    with pytest.raises(ScopeKindMismatchError) as mismatch:
        await a.authorize(U1, "design.read", ScopeRef("global", "*"))
    assert str(mismatch.value) == (
        "permission design.read belongs to scope kind studio, not global"
    )
    with pytest.raises(PermissionDeniedError) as denied:
        await a.authorize(U1, "design.delete", S1)
    assert denied.value.scope == S1 and denied.value.required == "design.delete"


@pytest.mark.asyncio
async def test_explain_reasons_for_resource_grant_and_attributes(catalog):
    # a loader that says "no such resource": not visible, with its own reason
    a, _ = await build(catalog, pol("o", Effect.REQUIRE, ("design.write",), OWNER))
    gone = ResourceContext(ResourceRef("design", "d1"), lambda r, f: None)
    e = await a.explain(U1, "design.write", S1, resource=gone)
    assert (e.kind, e.reason, e.visible, e.rbac_granted) == (
        DecisionKind.NOT_VISIBLE,
        "resource not found",
        True,
        True,
    )

    # grant mode, the role does not grant it and no permit applies: denied by the role
    g, _ = await build(
        catalog,
        pol("p", Effect.PERMIT, ("design.delete",), {"eq": [CLEAR, 99]}),
        mode="grant",
    )
    e = await g.explain(U1, "design.delete", S1)
    assert (e.kind, e.reason, e.rbac_granted) == (
        DecisionKind.DENIED,
        "role does not grant it",
        False,
    )
    assert e.outcome is not None and e.outcome.permitted is False

    # grant mode with a permit that holds: allowed by the policy, reason names it
    g2, _ = await build(
        catalog, pol("p", Effect.PERMIT, ("design.delete",)), mode="grant"
    )
    e = await g2.explain(U1, "design.delete", S1)
    assert (e.kind, e.reason, e.rbac_granted) == (
        DecisionKind.ALLOWED,
        "permit:p",
        False,
    )

    # a hide policy: the reason is the policy's, never an empty string
    h, _ = await build(catalog, pol("h", hide=True))
    e = await h.explain(U1, "design.read", S1)
    assert (e.kind, e.reason) == (DecisionKind.NOT_VISIBLE, "deny:h")


@pytest.mark.asyncio
async def test_the_abac_context_keeps_the_assignment_attributes(catalog):
    assignments = InMemoryAssignmentStore()
    await assignments.assign(
        NewAssignment("u1", S1, "EDI", {"tenant_status": "active"})
    )
    store = InMemoryPolicyStore()
    await store.create(pol("shadow", enforce=False, cond={"eq": [CLEAR, 99]}))
    pdp = PolicyDecisionPoint(store, AttributeResolver.default())
    a = Authorizer(catalog, [AssignmentRoleResolver(assignments)], pdp=pdp)
    ctx = await a.authorize(U1, "design.read", S1)
    assert ctx.attributes == {"tenant_status": "active"}


@pytest.mark.asyncio
async def test_authorize_and_explain_pass_the_request_to_the_providers(catalog):
    from auth_middleware.authz import PermissionDeniedError

    a, _ = await build(
        catalog, pol("no-delete", cond={"eq": [{"attr": "env.method"}, "DELETE"]})
    )
    with pytest.raises(PermissionDeniedError):
        await a.authorize(U1, "design.read", S1, request=request("DELETE"))
    ctx = await a.authorize(U1, "design.read", S1, request=request("GET"))
    assert ctx.policy_ids == ()
    e = await a.explain(U1, "design.read", S1, request=request("DELETE"))
    assert (e.kind, e.reason) == (DecisionKind.DENIED, "deny:no-delete")
    e = await a.explain(U1, "design.read", S1, request=request("GET"))
    assert e.kind is DecisionKind.ALLOWED
