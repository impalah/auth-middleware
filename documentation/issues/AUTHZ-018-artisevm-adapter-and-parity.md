# AUTHZ-018 · ARTISEVM: store adapter, wiring and parity tests

Epic G · Size L · **Repo: artisevm** (`/home/linus/projects/pinturilla/artisevm`) ·
Depends on: auth-middleware `0.7.0` available (PyPI, or `uv add --editable ../../auth-middleware`
during development); Q4 approved by the owner.

## Before starting (ARTISEVM rules, from `/home/linus/projects/pinturilla/CLAUDE.md` and the app's)

- Python 3.14 and **uv only**. Docs in Spanish, code and commits in English. Commits small, trailer
  `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`, never `push --force`.
- Changing an accepted architecture decision needs a **new ADR in `docs/adr/` and the owner's approval**
  (D-003 describes memberships and groups; ADR numbering continues from the last `ADR-APP-0NN`).
  Write the ADR first (it can be a short one: "Authorization mechanism moves to auth-middleware; catalog and
  membership rules stay"), get the approval, then code. Update `docs/CONSTITUTION.md` with a history line
  following its edit protocol.
- Do not touch `pictufy-analysis/`, `pinturilla-functional/`, `pinturilla-functional-v2/`.
- Nothing is applied to AWS and nothing is deployed in this work; it is code and tests only.
- This work happens after phase 10 closes (the owner decides the phase; do not start it inside phase 10).

## Context

Today (verified 2026-11-14):

- `application/identity/authorization.py::StudioAuthorizer.authorize(sub, permission, correlation_id)`
  returns a `RequestContext(sub, subject_id, email, studio_id, role, permissions, studio_status,
  correlation_id)` or raises `StudioNotVisibleError` / `PermissionDeniedError`.
- `api/authorization.py::require_studio_permission(permission)` maps them to 404 / 403
  `{"error": "forbidden", "required_permission": ...}`.
- `composition.py` ~190-225: `get_membership_repo` calls `set_studio_scope(session, scope.studio_id)`
  (RLS) as the first statement of the request transaction and returns `SqlMembershipRepository`;
  `get_studio_authorizer` builds the authorizer from `SubjectRepoDep`, `StudioRepoDep`,
  `MembershipRepoDep`.
- Membership role values are `Role` codes `TIT`, `EDI`, `LEC` (`domain/identity/permissions.py`).

## Scope

New `backend/src/artisevm/infrastructure/identity/authz_adapter.py` and changes in `composition.py` and
`api/authorization.py`. The existing `StudioAuthorizer` stays as a thin shim until AUTHZ-020 removes it.

## Design

1. `MembershipAssignmentStore` implements the library's `AssignmentStore` over the existing repositories:

```python
class MembershipAssignmentStore:
    def __init__(self, subjects: SubjectRepository, studios: StudioRepository, memberships: MembershipRepository): ...
    async def get_assignment(self, principal_id: str, scope: ScopeRef) -> Assignment | None:
        # scope.kind == "studio"; scope.id must equal str(memberships.studio_id) (the studio of the route)
        # subject = subjects.get_by_sub(principal_id); studio = studios.get(UUID(scope.id))
        # None if subject or studio is missing, or no membership (indistinguishable on purpose)
        # Assignment(principal_id, scope, role=membership.role.value, status=ACTIVE|REVOKED,
        #            revision=..., attributes={"subject_id": ..., "email": ..., "studio_id": ...,
        #                                       "studio_status": studio.status.value, "display_name": ...})
    async def list_assignments(self, principal_id: str) -> Sequence[Assignment]: ...   # raise NotImplementedError: not used by the guard
```

2. In `composition.py`, build the library runtime once in the application factory:
   `Authz.build(catalog=..., store_factory=membership_store_factory, error_policy=...)` and `install` it
   on the studio app (and on each mounted app that uses the guard, or pass `authz=` explicitly). The
   `store_factory(request)` must obtain `SubjectRepoDep`, `StudioRepoDep`, `MembershipRepoDep` for the
   request. **Ordering is the security property**: `set_studio_scope` must run before the first read of
   `membership`. Prefer making the factory resolve `get_membership_repo` through FastAPI's dependency
   system (a dependency on the route) rather than building repositories by hand.
3. `require_studio_permission(permission)` becomes a wrapper around the library's `require_permission`
   with `scope=ScopeFromPath("studio", "studio_id")`, and rebuilds `RequestContext` from `AuthzContext`
   (`role = next(iter(roles))`, `permissions = context.permissions`, `studio_status` from attributes,
   `correlation_id` from `request.state`). Routes do not change.
4. `ErrorPolicy`: `not_visible` -> `HTTPException(404)`; `denied` -> the same 403 detail as today (the
   library default already matches); keep ARTISEVM's problem handlers untouched.
5. Settings: cache off (Q1). Group mapping for platform admin comes in AUTHZ-020.

## Acceptance criteria (parity is the criterion; no new behaviour)

- [ ] `backend/tests/unit/test_studio_authorization.py` passes **unchanged** (every role x every
  permission and the 404/403 rule, TEST-PIN-036).
- [ ] `backend/tests/architecture/test_rest_authorization.py` and `test_hostile_tokens.py` pass unchanged.
- [ ] The RLS integration tests (`make test-integration`) pass: a request for studio B with a member
  token of studio A gets 404 and the membership query only ever sees studio A rows. Add one test that
  fails if the factory reads the membership **before** `set_studio_scope` (mutation: move the call and
  watch it fail).
- [ ] The 43 `require_studio_permission` call sites compile and keep their `x-permission` OpenAPI
  extensions (`make openapi-check`).
- [ ] No extra database round trips per request versus today (compare statement counts on one route with
  the SQL event listener; document the numbers in the PR).
- [ ] `make ci` equivalents that need no AWS pass (`make lint typecheck test-unit test-architecture`).

## Out of scope

Catalog generation (019), group-based platform admin (020), removing `tokens.py` duplicates (021).
