# AUTHZ-024 · Condition language: parser, limits, three-valued evaluator

Epic H · Size L · Depends on: 023 · Blocks: 025, 027

## Context

`PLAN-abac.md` section 2.2. The only place where policy data becomes behaviour, so it must be small,
closed and total.

## Scope

`src/auth_middleware/authz/abac/conditions.py`, `tests/authz/abac/test_conditions.py`.

## Design

```python
class Tri(Enum): TRUE; FALSE; INDETERMINATE

def parse_condition(raw: Mapping[str, Any], *, limits: ConditionLimits = DEFAULT) -> Condition  # frozen AST
def evaluate(cond: Condition, attrs: AttributeView) -> Tri                                     # pure, sync, total
```

Grammar (each node is a one-key dict):

- `{"all": [c, ...]}`, `{"any": [c, ...]}`, `{"not": c}`.
- `{"eq"|"ne"|"lt"|"lte"|"gt"|"gte": [a, b]}`.
- `{"in"|"not_in": [a, set]}`, `{"contains": [collection, a]}`, `{"intersects"|"subset": [a, b]}`.
- `{"starts_with"|"ends_with": [string, string]}`.
- `{"exists": {"attr": path}}`.
- Operand: JSON literal (str, int, float, bool, null, list of those) or `{"attr": "ns.path"}`.
- `{"now": ...}` is **not** an operator: time is the attribute `env.now` (injectable clock, testable).

Semantics:

- Missing attribute -> operand is *absent*; any comparison with an absent operand is INDETERMINATE;
  `exists` is the only operator that turns absence into FALSE/TRUE.
- Type mismatch (`lt` of str and int) -> INDETERMINATE (never raises at evaluation time).
- `all`: FALSE if any FALSE; else INDETERMINATE if any; else TRUE. `any`: dual. `not`: INDETERMINATE stays.
- Datetimes: attributes declared `datetime` (AUTHZ-025) are compared as aware UTC `datetime`s; literals
  are ISO-8601 strings with offset; naive values are INDETERMINATE.
- No regex, no arithmetic, no function calls, no user-defined operators.

Limits (`ConditionLimits`, defaults): depth 8, nodes 64, list literal 100 items, string literal 256
chars, attribute path 128 chars. Enforced in `parse_condition` (-> `ConditionError` with the JSON
pointer of the offending node) **and** re-checked in `evaluate` against a recursion guard.

## Acceptance criteria

- [ ] Truth table tests for every operator with TRUE/FALSE/INDETERMINATE inputs.
- [ ] `parse_condition(cond_to_dict(c)) == c` round trip; unknown operator / extra keys / wrong arity
  raise `ConditionError` with a pointer.
- [ ] Limits tests: depth 9, 65 nodes, 101-item list, huge string all rejected; a 64-node valid tree
  evaluates in < 1 ms (benchmark test, generous bound).
- [ ] Hostile input (deeply nested lists, `{"attr": "__class__"}`, `$`-prefixed keys, NaN/inf, bool vs
  int confusion `True == 1`) never raises anything but `ConditionError` at parse, never at evaluation.
- [ ] `bool` is not equal to `int`: `{"eq": [true, 1]}` is FALSE.
- [ ] No `eval/exec/re` imports (a test greps the module).

## Out of scope

Attribute resolution (026), schema typing of attributes (025).
