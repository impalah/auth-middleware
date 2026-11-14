# AUTHZ-034 · Audit, metrics, explain and shadow mode

Epic H · Size S · Depends on: 027

## Scope

`runtime.py` (`DecisionEvent`), `events.py`, `guards.py::_emit`, `tests/authz/abac/test_abac_events.py`.

## Design

- `DecisionEvent` gains `policy_ids: tuple[str, ...] = ()` (policies that **decided**), `shadow_policy_ids`
  (enforce=False policies that *would have* denied) and `abac_reason: str | None` (`"deny:<id>"`,
  `"require:<id>"`, `"indeterminate:<id>"`, `"permit:<id>"`). Existing fields unchanged; `to_dict` adds
  them only when non-empty. Events carry ids and names only: **never attribute values** (PII).
- `audit_hook`: a denial by policy logs at WARNING, a shadow denial at INFO with `shadow=true`.
- `metrics_hook` / `MetricsCollector.record_authz_decision` get an optional `source` label
  (`rbac` | `abac`); counters for `abac_policy_evaluations_total{policy_id,result}` capped to the
  100 most frequent ids (cardinality guard).
- Shadow rollout recipe in the docs: add policy with `enforce=false`, watch `shadow_policy_ids` for a
  week, flip with `replace`.
- `Authorizer.explain` output redacts attribute values by default (`reveal=True` only from the CLI).

## Acceptance criteria

- [ ] An ABAC denial event has `kind=denied`, the policy id and no attribute values (test greps the
  serialised event for a sentinel value).
- [ ] A shadow policy produces `shadow_policy_ids` and does not change the HTTP status.
- [ ] 0.7.0 events are unchanged when ABAC is off (golden dict test).
- [ ] Metrics cardinality cap test (1000 distinct ids -> bounded series).
