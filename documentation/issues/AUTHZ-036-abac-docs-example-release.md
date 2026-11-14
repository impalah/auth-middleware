# AUTHZ-036 · Docs, example, CHANGELOG, `0.8.0`

Epic H · Size M · Depends on: all of Epic H

## Scope

`pages_source/` (new `abac.rst`: concepts, condition reference, cookbook, rollout with shadow mode,
store setup SQL/DynamoDB, extending attribute providers; update index and the catalog reference),
`examples/abac_example.py` (runnable FastAPI app: suspended-tenant gate, owner-only delete, office-hours
support access, classification vs clearance), `documentation/CHANGELOG.txt` entry `0.8.0`,
`make docs` (the only issue allowed to regenerate `docs/`), version bump via `make bump-version PART=minor`
**only when the owner says to release**.

## Acceptance criteria

- [ ] `mode="grant"` is documented as experimental (semantics may be refined in a minor release).
- [ ] The 5 s policy cache and its cross-process staleness are documented in the operations section.
- [ ] Every example policy in the docs is a test fixture that parses and validates (docs cannot rot).
- [ ] Upgrade notes: no action needed unless `abac=` is configured; Alembic revision to run for SQL.
- [ ] Migration page: how to express ARTISEVM's tenant-status gate as a policy (reference, not coupled).
- [ ] `make check`, full test suite, Floci suite green; 3.12/3.13/3.14 matrix green in CI.
- [ ] Index in `documentation/issues/README.md` updated with the resolution log.
- [ ] `docs/` regenerated and committed in the same release commit; version bumped once.
