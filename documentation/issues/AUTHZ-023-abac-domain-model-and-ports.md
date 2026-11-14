# AUTHZ-023 · ABAC domain model, errors and ports

Epic H · Size M · Depends on: none · Blocks: 024, 026, 029

## Context

`PLAN-abac.md` sections 2.1, 2.5. This issue only adds vocabulary and ports; no behaviour.

## Scope

`src/auth_middleware/authz/abac/__init__.py`, `abac/types.py`, extend `errors.py` and `ports.py`,
`tests/authz/abac/test_types.py`.

## Design

```python
class Effect(StrEnum): DENY = "deny"; REQUIRE = "require"; PERMIT = "permit"

@dataclass(frozen=True, slots=True)
class PolicyScope:            # kind (+ optional id); id None = every scope of the kind
    kind: str; id: str | None = None

@dataclass(frozen=True, slots=True)
class Policy:
    id: str                    # [a-z0-9][a-z0-9_.-]{0,99}
    effect: Effect
    permissions: tuple[str, ...]      # exact or "*"-pattern, 1..50 entries
    scope: PolicyScope
    condition: Mapping[str, Any]      # raw AST, parsed by AUTHZ-024
    description: str = ""
    priority: int = 0                 # lower evaluated first (only affects explain order)
    hide: bool = False
    enforce: bool = True
    status: AssignmentStatus = ACTIVE
    revision: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None

@dataclass(frozen=True, slots=True)
class EntityRef:                      # who owns attributes
    namespace: Literal["principal", "resource"]; kind: str; id: str

@dataclass(frozen=True, slots=True)
class EntityAttributes:  ref: EntityRef; attributes: Mapping[str, Any]; revision: int = 0
@dataclass(frozen=True, slots=True)
class NewPolicy: ...                  # Policy without status/revision/timestamps
```

Ports (`ports.py`, all `runtime_checkable` Protocols, same style as `AssignmentStore`):

- `PolicyStore.list_policies(scope: ScopeRef) -> Sequence[Policy]`: returns the **active** policies whose
  `PolicyScope` matches `scope` exactly or by kind (scope id and kind-wide ones); plus
  `list_all(status=None)` for tooling/cache.
- `PolicyAdmin`: `create(NewPolicy)`, `replace(policy_id, NewPolicy, *, expected_revision)`,
  `set_status(policy_id, status, *, expected_revision)`, `get(policy_id)`. Same revision semantics as
  `AssignmentAdmin` (first revision 0, +1 per write, stale -> `RevisionConflictError`).
- `AttributeStore.get_attributes(ref) -> EntityAttributes | None`,
  `put_attributes(ref, attributes, *, expected_revision | None)`, `delete_attributes(ref, *, expected_revision)`.
  Attribute values are JSON scalars, lists of scalars (<= 100) or nested maps (depth <= 3); total size
  <= 4 KB (the DynamoDB `attrs_json` limit).

Errors: `PolicyError(AuthzError)`, `InvalidPolicyError`, `PolicyConflictError` (id exists),
`ConditionError(InvalidPolicyError)` (used by 024).

## Acceptance criteria

- [ ] Types validate their invariants in `__post_init__` (ids, pattern syntax, sizes) with `ValueError`.
- [ ] Types are frozen, hashable where the 0.7.0 ones are, round-trip to/from `dict` (`to_dict` /
  `from_dict`) so stores share one serialisation.
- [ ] `import auth_middleware.authz` is unchanged in cost and surface (abac exported lazily; test).
- [ ] Docstrings with `Args:/Returns:/Raises:`; mypy strict clean.

## Out of scope

Evaluation (024), implementations (029+).
