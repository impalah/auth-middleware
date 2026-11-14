from __future__ import annotations

import pytest

from auth_middleware.authz import (
    AssignmentChange,
    AssignmentService,
    PermissionCatalog,
    PermissionSpec,
    RevisionConflictError,
    ScopeKind,
    ScopeKindMismatchError,
    ScopeRef,
    UnknownRoleError,
)
from auth_middleware.authz.stores import InMemoryAssignmentStore

S = ScopeRef("studio", "s1")


class LastOwnerRequired(Exception):
    pass


@pytest.mark.asyncio
async def test_validation_and_round_trip(catalog):
    store = InMemoryAssignmentStore()
    service = AssignmentService(store, catalog)
    with pytest.raises(UnknownRoleError):
        await service.assign("u", S, "NOPE")
    with pytest.raises(ValueError):  # UnknownRoleError is also a ValueError
        await service.assign("u", S, "NOPE")
    with pytest.raises(ScopeKindMismatchError):
        await service.assign("u", S, "PLATFORM_ADMIN")
    first = await service.assign("u", S, "READER")
    changed = await service.change_role("u", S, "EDITOR", expected_revision=0)
    assert changed.revision == first.revision + 1
    with pytest.raises(RevisionConflictError):
        await service.change_role("u", S, "OWNER", expected_revision=0)
    assert [a.principal_id for a in await service.members(S)] == ["u"]
    revoked = await service.revoke("u", S, expected_revision=1)
    assert revoked.status.value == "revoked"


@pytest.mark.asyncio
async def test_before_change_veto_leaves_store_untouched(catalog):
    store = InMemoryAssignmentStore()
    seen: list[AssignmentChange] = []

    async def veto(change: AssignmentChange) -> None:
        seen.append(change)
        raise LastOwnerRequired

    service = AssignmentService(store, catalog, before_change=[veto])
    with pytest.raises(LastOwnerRequired):
        await service.assign("u", S, "OWNER")
    assert await store.get_assignment("u", S) is None
    assert seen[0].kind == "assign" and seen[0].old is None


@pytest.mark.asyncio
async def test_last_owner_rule_as_application_hook(catalog):
    store = InMemoryAssignmentStore()

    async def last_owner(change: AssignmentChange) -> None:
        leaving = change.kind == "revoke" or (
            change.kind == "change_role" and change.new_role != "OWNER"
        )
        if leaving and change.old and change.old.role == "OWNER":
            owners = [
                a
                for a in await store.list_for_scope(change.scope)
                if a.role == "OWNER" and a.status.value == "active"
            ]
            if len(owners) <= 1:
                raise LastOwnerRequired

    service = AssignmentService(store, catalog, before_change=[last_owner])
    await service.assign("o1", S, "OWNER")
    with pytest.raises(LastOwnerRequired):
        await service.revoke("o1", S, expected_revision=0)
    await service.assign("o2", S, "OWNER")
    await service.revoke("o1", S, expected_revision=0)


@pytest.mark.asyncio
async def test_after_change_receives_written_assignment(catalog):
    store = InMemoryAssignmentStore()
    got = []

    async def after(change, written):
        got.append((change.kind, written.role, written.revision))

    service = AssignmentService(store, catalog, after_change=[after])
    await service.assign("u", S, "READER")
    await service.change_role("u", S, "EDITOR", expected_revision=0)
    assert got == [("assign", "READER", 0), ("change_role", "EDITOR", 1)]


@pytest.mark.asyncio
async def test_after_change_not_called_when_write_fails(catalog):
    store = InMemoryAssignmentStore()
    called = []

    async def after(change, written):
        called.append(1)

    service = AssignmentService(store, catalog, after_change=[after])
    await service.assign("u", S, "READER")
    with pytest.raises(RevisionConflictError):
        await service.assign("u", S, "READER")
    assert called == [1]


@pytest.mark.asyncio
async def test_admin_without_reader_port_falls_back_to_list_for_scope(catalog):
    inner = InMemoryAssignmentStore()

    class AdminOnly:
        assign = inner.assign
        change_role = inner.change_role
        revoke = inner.revoke
        list_for_scope = inner.list_for_scope

    seen = []

    async def before(change):
        seen.append(change.old)

    service = AssignmentService(AdminOnly(), catalog, before_change=[before])  # type: ignore[arg-type]
    await service.assign("u", S, "READER")
    await service.change_role("u", S, "EDITOR", expected_revision=0)
    assert seen[0] is None and seen[1].role == "READER"
    assert PermissionCatalog and PermissionSpec and ScopeKind  # imports used
