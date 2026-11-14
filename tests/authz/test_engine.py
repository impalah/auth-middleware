from __future__ import annotations

import asyncio

import pytest

from auth_middleware.authz import (
    AssignmentRoleResolver,
    Authorizer,
    DecisionKind,
    GroupRoleResolver,
    NewAssignment,
    PermissionDeniedError,
    Principal,
    ScopeKindMismatchError,
    ScopeNotVisibleError,
    ScopeRef,
    UnknownPermissionError,
)
from auth_middleware.authz.stores import InMemoryAssignmentStore

S = ScopeRef("studio", "s1")
OTHER = ScopeRef("studio", "s2")
A, D, N = DecisionKind.ALLOWED, DecisionKind.DENIED, DecisionKind.NOT_VISIBLE


@pytest.fixture
def store():
    st = InMemoryAssignmentStore()

    async def fill():
        await st.assign(NewAssignment("owner", S, "OWNER", {"status": "active"}))
        await st.assign(NewAssignment("editor", S, "EDITOR"))
        await st.assign(NewAssignment("reader", S, "READER"))
        await st.assign(NewAssignment("nobody", S, "NOBODY"))
        r = await st.assign(NewAssignment("revoked", S, "OWNER"))
        await st.revoke("revoked", S, expected_revision=r.revision)

    asyncio.run(fill())
    return st


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "who,permission,scope,expected",
    [
        ("owner", "members.manage", S, A),
        ("editor", "design.write", S, A),
        ("editor", "members.manage", S, D),
        ("reader", "design.read", S, A),
        ("reader", "design.write", S, D),
        ("nobody", "design.read", S, D),
        ("stranger", "design.read", S, N),
        ("revoked", "design.read", S, N),
        ("owner", "design.read", OTHER, N),
    ],
)
async def test_decision_table(catalog, store, who, permission, scope, expected):
    authorizer = Authorizer(catalog, [AssignmentRoleResolver(store)])
    assert await authorizer.check(Principal(who), permission, scope) is expected


@pytest.mark.asyncio
async def test_authorize_returns_context_and_raises(catalog, store):
    authorizer = Authorizer(catalog, [AssignmentRoleResolver(store)])
    ctx = await authorizer.authorize(Principal("owner"), "design.write", S)
    assert ctx.roles == {"OWNER"}
    assert "members.manage" in ctx.permissions
    assert ctx.attributes == {"status": "active"}
    with pytest.raises(ScopeNotVisibleError):
        await authorizer.authorize(Principal("stranger"), "design.read", S)
    with pytest.raises(PermissionDeniedError) as exc:
        await authorizer.authorize(Principal("reader"), "design.write", S)
    assert exc.value.required == "design.write"
    assert "@" not in str(exc.value)


@pytest.mark.asyncio
async def test_programming_errors(catalog, store):
    authorizer = Authorizer(catalog, [AssignmentRoleResolver(store)])
    with pytest.raises(UnknownPermissionError):
        await authorizer.authorize(Principal("owner"), "nope", S)
    with pytest.raises(ScopeKindMismatchError):
        await authorizer.authorize(Principal("owner"), "design.read", ScopeRef.GLOBAL)


@pytest.mark.asyncio
async def test_hide_existence_false_gives_denied(catalog):
    authorizer = Authorizer(catalog, [GroupRoleResolver({"admins": "PLATFORM_ADMIN"})])
    admin = Principal("a", groups=("admins",))
    assert await authorizer.check(admin, "platform.admin", ScopeRef.GLOBAL) is A
    assert (
        await authorizer.check(
            Principal("b", groups=("x",)), "platform.admin", ScopeRef.GLOBAL
        )
        is D
    )


@pytest.mark.asyncio
async def test_group_resolver():
    resolver = GroupRoleResolver({"g1": "R1", "g2": "R2"})
    both = await resolver.resolve(
        Principal("u", groups=("g1", "g2", "zz")), ScopeRef.GLOBAL
    )
    assert both is not None and both.roles == {"R1", "R2"}
    assert (
        await resolver.resolve(Principal("u", groups=("zz",)), ScopeRef.GLOBAL) is None
    )
    assert await resolver.resolve(Principal("u", groups=("g1",)), S) is None


@pytest.mark.asyncio
async def test_roles_union_and_attributes_later_wins(catalog, store):
    class Late:
        async def resolve(self, principal, scope):
            from auth_middleware.authz import ResolvedRoles

            return ResolvedRoles(frozenset({"READER"}), {"status": "late"})

    authorizer = Authorizer(catalog, [AssignmentRoleResolver(store), Late()])
    ctx = await authorizer.authorize(Principal("owner"), "design.read", S)
    assert ctx.roles == {"OWNER", "READER"}
    assert ctx.attributes["status"] == "late"
