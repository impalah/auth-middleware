# AUTHZ-020 · ARTISEVM: swap the guards, platform admin as a role

Epic G · Size M · **Repo: artisevm** · Depends on: 018, 019

Same ARTISEVM rules as AUTHZ-018.

## Context

Group-based gates today (all through the library's `GroupChecker`, flat any-of lists):

| Guard | File | Setting | Used by |
|---|---|---|---|
| `require_reader` / `require_writer` | `api/dependencies.py` | `rest_read_groups`, `rest_write_groups` (both `artisevm-studio-members`) | `/me` entry gate (`api/routes/session.py`) |
| `require_platform_admin` | `platform_api/dependencies.py` | `platform_admin_groups` | 6 uses on the platform surface |
| web `require_reader`/`require_admin`/`require_company_account` | `web/dependencies.py`, `web/routes/showroom.py` | the same groups on the **session**, not a token | HTMX showroom: **stays** |

The doc-05 matrix already has a `PLA` role (`platform.studio.manage`), so the platform surface can use the
same mechanism as the studio instead of a bespoke group check.

## Scope

`platform_api/dependencies.py`, `platform_api/app.py`, `api/dependencies.py`, `composition.py`, settings if
a setting is renamed (avoid: keep `platform_admin_groups`), tests.

## Design

1. Platform surface: `Authz.build(..., group_roles={g: "PLA" for g in settings.platform_admin_groups},
   group_scope_kind="global")` on the platform app (its own `install`, its own audience middleware as
   today). `require_platform_admin` becomes
   `require_permission("platform.studio.manage", scope=GlobalScope())`.
   Outcome must be identical: no group -> **403** (global scope kind has `hide_existence=False`), no user -> 401.
2. `/me` entry gate: keep the library's flat `require_groups(rest_read_groups)` (it is plain RBAC at the edge:
   "is this person staff of any studio at all"). Replace the local `_require_any_group` wrapper only if it
   becomes identical to the library function; keep the development-placeholder bypass
   (`rest_auth != "oidc"` returns early) exactly as it is.
3. Web (HTMX) guards are untouched (no JWT; session roles).
4. Delete the now-unused `StudioAuthorizer` shim if nothing imports it (seeds import it today:
   `entrypoints/seed*.py` build `StudioAuthorizer(bound.subjects, bound.studios, bound.memberships)`; either
   keep a small non-HTTP helper for seeds or move them to the library `Authorizer` with an
   in-process store; choose the smaller diff and note it).

## Acceptance criteria

- [ ] Platform surface tests unchanged and green (admin 200, non-admin 403, anonymous 401, studio token on
  the platform app refused by audience as today).
- [ ] `test_rest_authorization.py` still enumerates every operation of every surface and demands a guard.
- [ ] The seeds run (`make demo`/`tools/seed.sh` in a dev stack; if AWS is unavailable, run their unit
  tests) and create the same data.
- [ ] No behaviour change visible in OpenAPI except `x-permission` on the platform operations (add it to
  the allowed differences of the conformance check if the check complains, and say so in the PR).

## Out of scope

Company accounts and guests.
