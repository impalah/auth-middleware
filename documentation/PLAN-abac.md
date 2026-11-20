# PLAN · ABAC (attribute-based access control) on top of scoped permissions

Status: proposed (2026-11-14). Nothing in this plan is implemented yet.
Issues: `documentation/issues/AUTHZ-023..036` (Epic H; index in `documentation/issues/README.md`).
Target release: `0.8.0` (additive: with no policy configured, behaviour is byte-for-byte the 0.7.0 one).
Read first: `PLAN-authz.md` (vocabulary: scope, assignment, catalog, `Authorizer`).

## 1. Why

0.7.0 answers "may principal P do permission X in scope S?" through **roles** (an assignment gives a
role in a scope; the catalog maps role -> permissions). That cannot express rules that depend on *data*:

- "no writes while the studio is `suspended`" (today: hard-coded in the application, ARTISEVM's tenant
  status gate);
- "only the owner of a design may delete it, even for an `editor`";
- "documents classified `secret` need clearance >= 3 and a managed network";
- "support staff may read, but only 08:00-20:00 and never `billing.*`".

These are **attribute** conditions over the *subject* (who), the *resource* (what), the *action* and the
*environment* (when/where). ABAC adds them **without replacing** RBAC: roles stay the coarse grant,
policies refine it and are stored in the same persistence engines (SQLAlchemy, DynamoDB).

## 2. Design decisions (proposed; the owner confirms the open questions in section 8)

### 2.1 Policies are data, not code

A policy is a JSON-serialisable document, so it can be stored in SQL/DynamoDB, versioned, audited and
validated before it is accepted. **No `eval`, no embedded scripting language, no regular expressions.**

```json
{
  "id": "studio-suspended-readonly",
  "description": "A suspended studio cannot be modified",
  "effect": "deny",
  "permissions": ["*.write", "*.delete"],
  "scope": {"kind": "studio"},
  "condition": {"eq": [{"attr": "subject.assignment.tenant_status"}, "suspended"]},
  "priority": 0,
  "hide": false,
  "enforce": true
}
```

- `effect`: `deny` (wins always), `require` (an extra condition that must be TRUE, otherwise denied),
  `permit` (grants on its own; only honoured in `grant` mode, see 2.4).
- `permissions`: exact names or `*`-wildcard patterns over the catalog (`design.*`, `*.write`); a pattern
  that matches no catalog permission is rejected at write time.
- `scope`: `{"kind": K}` (every scope of the kind) or `{"kind": K, "id": I}` (one scope).
- `hide`: a failing policy answers 404 instead of 403 (resource existence must not leak).
- `enforce: false` = **shadow mode**: evaluated and reported in the audit event, never enforced.

### 2.2 Condition language (small, closed, total)

AST of plain dicts: `all` / `any` / `not`; comparisons `eq ne lt lte gt gte`; sets `in not_in contains
intersects subset`; strings `starts_with ends_with`; `exists`. Operands are literals or `{"attr": path}`.
Hard limits (depth, node count, literal size, set size) are checked at parse time and again at
evaluation. Evaluation is **three-valued** (TRUE / FALSE / INDETERMINATE: a missing attribute, a type
mismatch): INDETERMINATE in a `deny` applies the deny, in a `require`/`permit` it is "not satisfied"
(fail closed in both directions).

Rejected alternatives (Q3): Cedar (`cedarpy` is a native wheel, one more binary dependency and no
persistence story), OPA/Rego (sidecar + network hop per decision), CEL (`cel-python` is heavy and
Turing-incomplete-but-large), Casbin (its model language is a second DSL; adapters would duplicate our
stores). A ~300-line closed evaluator is auditable and has no dependency.

### 2.3 Attributes: four namespaces, declared in the catalog

| Namespace | Examples | Comes from |
|---|---|---|
| `subject.*` | `id`, `groups`, `email`, `claims.<name>`, `assignment.<name>`, `roles`, `attrs.<name>` | token (`Principal`), the assignment's `attributes`, and the persisted principal attributes (`AttributeStore`) |
| `resource.*` | `kind`, `id`, `attrs.<name>` | a **loader supplied by the route** (the application's own data), or the persisted resource attributes (`AttributeStore`) |
| `action.*` | `permission` | the permission being checked |
| `env.*` | `now`, `hour_utc`, `weekday`, `ip`, `method`, `path`, `header.<name>` (allow-listed) | the request |

The catalog gains an `attributes` section (name, type, namespace, required). Policies are validated
against it **when written** (unknown attribute, operator/type mismatch, unknown permission) so that a
typo is rejected at the CLI/service, not discovered as a silent INDETERMINATE in production.

### 2.4 Combining with RBAC (the safe order)

1. Unchanged 0.7.0 phase: scope kind check, visibility (404), roles -> permission (403).
2. ABAC phase (only when a policy source is configured): collect applicable enforced policies (scope +
   permission match), evaluate. **Deny-overrides**: any `deny` TRUE/INDETERMINATE -> denied; any
   `require` not TRUE -> denied; otherwise allowed.
3. `mode="restrict"` (default): ABAC can only **narrow** what RBAC granted. A bad policy can lock people
   out, never let anybody in. `mode="grant"` (opt-in): a `permit` policy whose condition is TRUE grants
   even if the role does not, but only for principals that are visible in the scope (a non-member still
   gets 404; ABAC never widens visibility).

### 2.5 Persistence: reuse the engines and their patterns

Same patterns as the assignment stores (optimistic `revision`, status active/revoked, `StoreUnavailableError`
on outages, injected sessions / PynamoDB models, lazy imports behind the existing extras; **no new extra**).

- New ports in `ports.py`: `PolicyStore` (read), `PolicyAdmin` (write), `AttributeStore`
  (read+write of principal/resource attributes). The in-memory stores and a **contract suite** in
  `auth_middleware.authz.testing` define the behaviour; SQL and DynamoDB must pass it.
- SQL: tables `authz_policy` and `authz_attribute` (JSON/JSONB), Alembic revision, MySQL `utf8mb4_bin`
  identifiers like the assignment table.
- DynamoDB (PynamoDB): policies under `pk=SCOPE#<kind>#<id|*>`, `sk=POLICY#<id>` (one Query per
  scope plus one for the kind-wide `*`), attributes under `pk=ENTITY#<ns>#<kind>#<id>`; separate table by
  default (`policy_table_name`), same table possible.
- Static policies can also come from a TOML/JSON file (like the catalog) through `StaticPolicySource`;
  sources are merged (static first, store second; ids must not clash).

### 2.6 Runtime and API

```python
authz = Authz.build(
    catalog=catalog,
    store_factory=...,
    abac=AbacConfig(
        policies=SqlPolicyStore(
            sessionmaker
        ),  # or Dynamo, memory, static, a list of several
        attributes=SqlAttributeStore(sessionmaker),  # optional
        mode="restrict",
        policy_cache_ttl=5.0,  # seconds; 0 disables (default)
    ),
)


@router.delete("/studios/{studio_id}/designs/{design_id}")
async def delete_design(
    ctx=Depends(
        require_permission(
            "design.delete",
            scope=ScopeFromPath("studio_id"),
            resource=ResourceFromPath("design", "design_id", loader=load_design_attrs),
        )
    ),
): ...
```

`loader(request, ref) -> Mapping[str, Any] | None`: returns the resource attributes from the
application's database; `None` = resource does not exist (same answer as "not visible"). `has_permission`
and `Authorizer.check/authorize/explain` accept the same `resource`.

### 2.7 Operability

- `Authorizer.explain(...)` returns the decision trace (which policies matched, which condition value);
  **never** sent to the client, only to logs/CLI. `DecisionEvent` gains `policy_ids` and `shadow_denials`.
- CLI: `authcli authz policy add|list|show|disable|enable|validate|test` (`test` evaluates a policy
  against a JSON context offline, no database).
- Policy changes are written with `expected_revision`, audited, and invalidate the snapshot cache.

## 3. Non-goals (this epic)

List filtering by pushing the policy into the query ("partial evaluation"; Q7), obligations/advice,
delegation, a policy-management HTTP API (the service + CLI are enough; a router can be a later
epic), distributed cache invalidation, any change to the legacy flat guards.

## 4. Epic H · issues (execution order)

| Id | Title | Size | Depends on |
|---|---|---|---|
| AUTHZ-023 | ABAC domain model, errors and ports | M | none |
| AUTHZ-024 | Condition language: parser, limits, three-valued evaluator | L | 023 |
| AUTHZ-025 | Attribute schema in the catalog and policy validation | M | 023, 024 |
| AUTHZ-026 | Attribute providers (subject, resource, environment) | M | 023 |
| AUTHZ-027 | Policy decision point and `Authorizer` integration | L | 024, 025, 026 |
| AUTHZ-028 | `Authz` runtime config and guard `resource=` | M | 027 |
| AUTHZ-029 | In-memory policy/attribute stores and contract suite | M | 023 |
| AUTHZ-030 | SQLAlchemy policy and attribute stores + migration | L | 029 |
| AUTHZ-031 | DynamoDB policy and attribute stores | L | 029 |
| AUTHZ-032 | `PolicyService`, static policy files and `authcli authz policy` | M | 025, 029 |
| AUTHZ-033 | Policy snapshot cache (default TTL 5 s) | S | 027, 029 |
| AUTHZ-034 | Audit, metrics, explain and shadow mode | S | 027 |
| AUTHZ-035 | Security hardening battery | M | 027, 030, 031 |
| AUTHZ-036 | Docs, example, CHANGELOG, `0.8.0` | M | all |

Critical path: 023 -> 024 -> 025 -> 027 -> 028; stores (029 -> 030/031) run in parallel from 023.

## 5. Risks

| Risk | Mitigation |
|---|---|
| A policy locks everybody out | `restrict` default, shadow mode, `authcli authz policy test`, validation at write time |
| Missing attribute silently skips a `deny` | three-valued logic, INDETERMINATE applies the deny; tests per operator |
| Hostile/huge policy exhausts CPU or memory | closed language, no regex, parse and evaluation limits, size limit at the store |
| Extra query per request (cost on DynamoDB) | snapshot cache on by default with a 5 s TTL (033) |
| Stale policy after a change in another process | short TTL, documented; invalidation on local writes; TTL 0 available |
| Resource loader leaks existence | loader `None` -> same not-visible answer; `hide` per policy |
| Scope creep into a policy server | non-goals above |

## 6. Compatibility

Everything lives in new modules plus optional parameters (`abac=`, `resource=`) that default to
`None`. `Authz.build` without `abac` does not touch ABAC code paths (a test asserts it). No new
dependency, no new extra. Alembic revision is additive (new tables only).

## 7. Test strategy

Unit (evaluator per operator and per three-valued case), property tests (Hypothesis, already in the
tool chain? if not, table-driven) for "any INDETERMINATE under deny denies", contract suite for stores,
moto + SQLite by default, PostgreSQL 17 and Floci (`make test-floci`) for the real engines, an
end-to-end FastAPI test per documented policy example.

## 8. Decisions and open questions

Resolved by the owner (2026-11-14):

- **Q1 (resolved)** `grant` mode ships in 0.8.0, documented as experimental.
- **Q3 (resolved)** Own condition language (closed, dependency-free).
- **Q5 (resolved)** Policy snapshot cache with a default TTL of 5 s (`AbacConfig.policy_cache_ttl = 5.0`;
  0 disables it). Assignments stay uncached.
- **Q6 (resolved)** Numbering stays `AUTHZ-0xx`.

Accepted as recommended (owner, 2026-11-14):

- **Q2 (resolved)** `hide` per policy (AUTHZ-027, 028).
- **Q4 (resolved)** Persisted resource attributes (`AttributeStore`) ship in 0.8.0 next to app-supplied
  loaders (AUTHZ-026, 029-031).
- **Q7 (resolved)** List filtering (partial evaluation) is a follow-up epic, not part of 0.8.0.
- **Q8 (resolved)** ARTISEVM's tenant-status gate is the reference example; Epic G is not a dependency.

All open questions are closed; Epic H can start at AUTHZ-023.
