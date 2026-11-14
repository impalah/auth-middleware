# AUTHZ-006 · In-memory store and the store contract suite

Epic A · Size M · Depends on: 001 · Blocks: 007, 009

## Context

Three backends must behave identically (in-memory, SQLAlchemy, DynamoDB) and applications will write
their own adapters (ARTISEVM's membership adapter, AUTHZ-018). One reusable, importable test suite is
how that is enforced.

## Scope

`src/auth_middleware/authz/stores/__init__.py`, `stores/memory.py`,
`src/auth_middleware/authz/testing/__init__.py`, `testing/contract.py`,
`tests/authz/test_memory_store.py`.

## Design

`InMemoryAssignmentStore` implements `AssignmentStore` **and** `AssignmentAdmin` with a dict guarded by
an `asyncio.Lock`. It is a real implementation (used by tests and examples), not a mock.

`testing/contract.py` ships a base class (importable by applications; it must NOT import pytest at module
import time beyond what `pytest` plugins need: use plain `async def` methods and a documented fixture
protocol):

```python
class AssignmentStoreContract:
    """Subclass, provide `make_store()` (async context manager yielding an object that is both
    AssignmentStore and AssignmentAdmin) and run with pytest-asyncio."""

    @abstractmethod
    def make_store(self) -> AsyncContextManager[AssignmentStore | AssignmentAdmin]: ...

    # test_* methods below
```

Contract cases (each a `test_...` method; names are stable, other issues refer to them):

1. `get_assignment` of an unknown principal/scope returns `None`.
2. `assign` then `get_assignment` returns the same role, `ACTIVE`, `revision == 0` (decide: first revision
   is 0), `created_at` set (timezone-aware UTC).
3. `assign` twice for the same (principal, scope) raises `RevisionConflictError`.
4. `change_role` with the right `expected_revision` bumps it by exactly 1; with a stale one raises.
5. `revoke` makes `status == REVOKED` and bumps revision; the engine view (`get_assignment`) may return
   it but it is not ACTIVE.
6. `assign` after `revoke` reactivates with `revision + 1` and the new role.
7. `list_assignments(principal)` returns all scopes of that principal and no one else's.
8. `list_for_scope(scope)` returns all principals of that scope and nothing from other scopes.
9. Scope isolation: same principal in two scopes keeps two independent assignments.
10. Attribute round trip: `attributes` set at `assign` (if the backend stores them) are returned;
    backends that do not store attributes must say so via a class flag `supports_attributes = False`
    and the case is skipped.
11. Concurrency: 20 concurrent `assign` for the same key -> exactly one succeeds, 19 raise
    `RevisionConflictError`.
12. Unicode and long ids (200 chars) round-trip.

## Acceptance criteria

- [ ] `InMemoryAssignmentStore` passes the whole contract.
- [ ] The contract is importable as `auth_middleware.authz.testing.AssignmentStoreContract` without
  importing sqlalchemy/aioboto3.
- [ ] A test proves the contract fails on a deliberately broken store (e.g. one that never bumps
  `revision`): mutation check, so the suite cannot pass vacuously.
- [ ] Revision semantics (first = 0, +1 per write) are written in the `ports.py` docstrings (AUTHZ-001).

## Out of scope

Persistent backends (007, 009).
