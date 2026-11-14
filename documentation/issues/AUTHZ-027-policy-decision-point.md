# AUTHZ-027 · Policy decision point and `Authorizer` integration

Epic H · Size L · `grant` mode is in scope for 0.8.0 (Q1, experimental) · Depends on: 024, 025, 026 · Blocks: 028, 033, 034, 035

## Context

`PLAN-abac.md` section 2.4. This is where ABAC meets the 0.7.0 `Authorizer.authorize`.

## Scope

`abac/pdp.py`, edits in `engine.py` (new optional constructor arg), `types.py` (`AuthzContext.policy_ids`),
`tests/authz/abac/test_pdp.py`, `tests/authz/test_engine_abac.py`.

## Design

```python
class PolicyDecisionPoint:
    def __init__(self, policies: PolicySource, resolver: AttributeResolver, *,
                 catalog: PermissionCatalog, mode: Literal["restrict", "grant"] = "restrict") -> None: ...
    async def decide(self, principal, permission, scope, *, resource, rbac_granted: bool,
                     visible: bool, assignment_attributes) -> AbacOutcome   # allowed/denied/hidden + trace
```

`Authorizer(catalog, resolvers, *, pdp: PolicyDecisionPoint | None = None)`. `pdp is None` -> the code path
is **exactly** 0.7.0 (a test asserts no ABAC import happens and results are identical on the existing
engine test-suite).

Algorithm in `authorize` (after the existing steps 1-3):

1. RBAC result as today. If `pdp is None`: finish as today.
2. Applicable policies: `PolicySource.list_policies(scope)`, filtered by permission pattern, `status`
   active. Shadow (`enforce=False`) ones are evaluated but only recorded.
3. Resolve needed attributes (lazy), evaluate each policy:
   - `deny`: TRUE or INDETERMINATE -> denied (`hide` -> 404 else 403).
   - `require`: not TRUE -> denied.
   - `permit`: TRUE -> candidate grant (only `mode="grant"`).
4. `restrict`: allowed iff RBAC allowed and no denial. `grant`: allowed iff (RBAC allowed or a TRUE permit)
   and no denial **and** the principal is visible in the scope (no assignment -> still
   `ScopeNotVisibleError`; ABAC never widens visibility).
5. Errors: unknown permission/scope kind mismatch unchanged. Provider/store failure ->
   `StoreUnavailableError` (503), never "allow".
6. Returns `AuthzContext` with `policy_ids` (policies that decided) and, via `explain`, a trace.

`Authorizer.explain(principal, permission, scope, resource=None) -> Explanation` runs the same path and
returns every policy considered with its value and the reason for the final decision (data class, for
logs/CLI; never serialised into an HTTP response by the library).

Determinism: policies sorted by `(priority, id)`; all of them are evaluated even after the first denial
**only when explaining or in shadow mode**; the enforcing path short-circuits on the first denial.

## Acceptance criteria

- [ ] Decision table test (RBAC yes/no x deny/require/permit x TRUE/FALSE/INDETERMINATE x restrict/grant
  x member/non-member): every row asserted.
- [ ] `restrict` can never turn a 403/404 into allowed (property test over random policies).
- [ ] `hide` turns a denial into the same `ScopeNotVisibleError` as a non-member (error text identical).
- [ ] INDETERMINATE `deny` denies; INDETERMINATE `require` denies; INDETERMINATE `permit` grants nothing.
- [ ] Source failure -> `StoreUnavailableError`, never allowed.
- [ ] Without `pdp`, the 0.7.0 engine tests pass untouched.
- [ ] Shadow policy never changes the outcome but appears in the trace.

## Out of scope

Guard/runtime wiring (028), caching (033), emitting events (034).
