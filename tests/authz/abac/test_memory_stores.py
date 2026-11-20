"""AUTHZ-029: in-memory ABAC stores and the contract suite."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import replace

import pytest

from auth_middleware.authz.abac.types import NewPolicy, Policy
from auth_middleware.authz.stores.memory import (
    InMemoryAttributeStore,
    InMemoryPolicyStore,
)
from auth_middleware.authz.testing import AttributeStoreContract, PolicyStoreContract


@pytest.mark.asyncio
class TestMemoryPolicyContract(PolicyStoreContract):
    @asynccontextmanager
    async def make_store(self):
        yield InMemoryPolicyStore()


@pytest.mark.asyncio
class TestMemoryAttributeContract(AttributeStoreContract):
    @asynccontextmanager
    async def make_store(self):
        yield InMemoryAttributeStore()


class _NeverBumps(InMemoryPolicyStore):
    """Deliberately broken: revisions never move."""

    async def replace(
        self, policy_id: str, new: NewPolicy, *, expected_revision: int
    ) -> Policy:
        result = await super().replace(
            policy_id, new, expected_revision=expected_revision
        )
        broken = replace(result, revision=0)
        self._items[policy_id] = broken
        return broken


class _BrokenContract(PolicyStoreContract):
    @asynccontextmanager
    async def make_store(self):
        yield _NeverBumps()


@pytest.mark.asyncio
async def test_contract_fails_on_broken_store():
    """Mutation check: the contract cannot pass vacuously."""
    with pytest.raises(AssertionError):
        await _BrokenContract().test_replace_checks_revision_and_bumps()
