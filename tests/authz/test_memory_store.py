from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import replace

import pytest

from auth_middleware.authz.stores.memory import InMemoryAssignmentStore
from auth_middleware.authz.testing import AssignmentStoreContract
from auth_middleware.authz.types import Assignment, NewAssignment


@pytest.mark.asyncio
class TestMemoryStoreContract(AssignmentStoreContract):
    @asynccontextmanager
    async def make_store(self):
        yield InMemoryAssignmentStore()


class _NeverBumps(InMemoryAssignmentStore):
    """Deliberately broken: revisions never move."""

    async def assign(self, new: NewAssignment) -> Assignment:
        result = await super().assign(new)
        self._items[(new.principal_id, new.scope)] = replace(result, revision=0)
        return replace(result, revision=0)


class _BrokenContract(AssignmentStoreContract):
    @asynccontextmanager
    async def make_store(self):
        yield _NeverBumps()


@pytest.mark.asyncio
async def test_contract_fails_on_broken_store():
    """Mutation check: the contract cannot pass vacuously."""
    with pytest.raises(AssertionError):
        await _BrokenContract().test_assign_after_revoke_reactivates()
