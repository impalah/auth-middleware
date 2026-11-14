# AUTHZ-025 · Attribute schema in the catalog and policy validation

Epic H · Size M · Depends on: 023, 024 · Blocks: 027, 032

## Context

A typo in an attribute name makes a `deny` INDETERMINATE for ever (which still denies, but for the wrong
reason) or a `require` never satisfiable. Policies must be checked against a declared schema before they
are stored or loaded.

## Scope

`catalog.py` (extension), `abac/schema.py`, `abac/validation.py`, `tests/authz/abac/test_validation.py`,
catalog TOML/JSON format documented in `pages_source/`.

## Design

Optional catalog section (absent = ABAC unavailable, catalogs of 0.7.0 load unchanged):

```toml
[attributes."subject.assignment.tenant_status"]
type = "string"            # string | int | float | bool | datetime | string_set
enum = ["active", "suspended"]   # optional
required = false           # true: a missing value is a configuration error at decision time? no: INDETERMINATE

[attributes."resource.attrs.classification"]
type = "int"
[attributes."env.now"]     # built-ins (subject.id, subject.groups, env.now, ...) are predeclared
```

`AttributeSchema` (immutable) is built by `PermissionCatalog` and exposed as `catalog.attributes`.
`validate_policy(policy, catalog) -> None` raises `InvalidPolicyError` listing **all** problems:

- every `permissions` entry matches at least one catalog permission; its scope kind equals
  `policy.scope.kind` for all matches (a pattern spanning kinds is rejected);
- scope kind exists in the catalog; `PolicyScope.id` only for kinds that are not `global`-only wildcards;
- every `{"attr": path}` is declared; operator operands type-check (`lt` needs int/float/datetime,
  `starts_with` needs string, `in` needs a set of the operand's type, enum values respected for literals);
- `effect = permit` is refused unless the catalog is used with `mode="grant"` (validation takes
  `allow_permit: bool`);
- `hide = true` only on `deny`/`require`.

`attrs.<name>` namespaces not declared are rejected (no free-form access).

## Acceptance criteria

- [ ] 0.7.0 catalog files still load (test with the existing fixtures).
- [ ] One test per rejection rule above, plus a multi-error policy listing every error.
- [ ] `catalog.attributes` is immutable; round trip `to_dict/from_file` keeps the section.
- [ ] Docs: catalog reference page updated (`pages_source/`), no `docs/` edits.

## Out of scope

Where values come from (026).
