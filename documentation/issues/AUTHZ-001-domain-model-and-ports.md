# AUTHZ-001 · Domain model, errors and ports

Epic A · Size M · Depends on: none · Blocks: 002, 003, 006

## Context

Everything in the scoped-permissions plan hangs on a small, dependency-free vocabulary and on the
ports that applications inject. Design: `PLAN-authz.md` sections 3.1 and 3.2. ARTISEVM reference
(read-only, for semantics): `artisevm/backend/src/artisevm/application/identity/authorization.py`
and `application/identity/ports.py` (`MembershipRepository`).

## Scope

Create the package `src/auth_middleware/authz/` with:

- `types.py`
- `errors.py`
- `ports.py`
- `__init__.py` exporting the public names (and nothing else; do NOT re-export from
  `auth_middleware/__init__.py` yet).

Tests in `tests/authz/test_types.py` and `tests/authz/test_errors.py`.

## Design

`types.py` (frozen dataclasses with `slots=True`, no pydantic: no validation cost on the hot path;
validate in constructors with `__post_init__`):

```python
GLOBAL_KIND = "global"


@dataclass(frozen=True, slots=True)
class ScopeRef:
    kind: str  # non-empty, [a-z][a-z0-9_]*
    id: str  # non-empty, <= 200 chars; "*" only for GLOBAL
    GLOBAL: ClassVar["ScopeRef"]  # ScopeRef(GLOBAL_KIND, "*")


class AssignmentStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class Principal:
    id: str  # the token `sub`
    groups: tuple[str, ...] = ()
    email: str | None = None


@dataclass(frozen=True, slots=True)
class Assignment:
    principal_id: str
    scope: ScopeRef
    role: str
    status: AssignmentStatus
    revision: int = 0
    created_at: datetime | None = None
    attributes: Mapping[str, Any] = field(
        default_factory=dict
    )  # free data a store attaches


@dataclass(frozen=True, slots=True)
class NewAssignment:
    principal_id: str
    scope: ScopeRef
    role: str


class DecisionKind(StrEnum):
    ALLOWED = "allowed"
    NOT_VISIBLE = "not_visible"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class AuthzContext:  # what a handler receives after a successful check
    principal: Principal
    scope: ScopeRef
    roles: frozenset[str]
    permissions: frozenset[str]
    attributes: Mapping[str, Any]  # merged attributes of the assignments that matched
```

`errors.py`: `AuthzError(Exception)`; `ScopeNotVisibleError(AuthzError)`;
`PermissionDeniedError(AuthzError)` with `.required: str` and `.scope: ScopeRef`;
`UnknownPermissionError`, `CatalogError`, `ScopeKindMismatchError`, `ConfigurationError` (all
`AuthzError`; the last four mean "programming/configuration mistake", never a request outcome);
`RevisionConflictError(AuthzError)` for optimistic writes (used by AUTHZ-007/009/011).

`ports.py` (all `typing.Protocol`, `@runtime_checkable`):

```python
class AssignmentStore(Protocol):
    async def get_assignment(
        self, principal_id: str, scope: ScopeRef
    ) -> Assignment | None: ...
    async def list_assignments(self, principal_id: str) -> Sequence[Assignment]: ...


class AssignmentAdmin(Protocol):
    async def assign(self, new: NewAssignment) -> Assignment: ...
    async def change_role(
        self, principal_id: str, scope: ScopeRef, role: str, *, expected_revision: int
    ) -> Assignment: ...
    async def revoke(
        self, principal_id: str, scope: ScopeRef, *, expected_revision: int
    ) -> Assignment: ...
    async def list_for_scope(self, scope: ScopeRef) -> Sequence[Assignment]: ...


StoreFactory = Callable[[Request], "AssignmentStore | Awaitable[AssignmentStore]"]
```

Semantics to write in the docstrings (they are the contract the test suite of AUTHZ-006 enforces):

- `get_assignment` returns `None` when the scope or the principal does not exist: the engine must not
  be able to tell them apart (this is what makes a 404 indistinguishable).
- A `REVOKED` assignment may be returned (history) but the engine treats it as absent.
- `assign` on an existing active assignment raises `RevisionConflictError`; on a revoked one it
  reactivates it with `revision + 1`.
- Every write bumps `revision` by exactly 1; a stale `expected_revision` raises
  `RevisionConflictError`.

## Acceptance criteria

- [ ] All names above exist, are typed under mypy strict and documented.
- [ ] `ScopeRef("Bad Kind", "x")`, empty ids and `ScopeRef("studio", "*")` raise `ValueError`.
- [ ] Dataclasses are hashable and immutable (a test tries to assign and expects `FrozenInstanceError`).
- [ ] `import auth_middleware.authz` imports no optional dependency (no sqlalchemy, no aioboto3).
- [ ] `isinstance(obj, AssignmentStore)` works for a class that only implements the two methods.

## Tests

Construction and validation, equality/hash, `GLOBAL`, error hierarchy and `.required`, protocol
conformance with a trivial fake.

## Docs

None yet (AUTHZ-014). Docstrings only.

## Out of scope

Catalog, engine, FastAPI. No storage code.
