# AUTHZ-022 · Decision record: memberships into library tables?

Epic G · Size S · Repos: both · Depends on: ARTISEVM 020 · **Decision only: do not implement**

## Context

After AUTHZ-018 ARTISEVM keeps its own `identity.membership` table behind an adapter, and the library's
SQLAlchemy/DynamoDB stores are used by *other* applications. The owner asked for the permission storage to
live in the library; whether ARTISEVM itself should migrate its memberships there is a separate decision
with real costs. Produce a short decision record (Spanish, in ARTISEVM `docs/adr/` as a **proposed** ADR,
plus a copy of the analysis as an appendix of this file) and stop for the owner's decision.

## What the record must answer (with evidence from the code)

1. **What ARTISEVM stores per membership today** (read `domain/identity/membership.py`,
   `infrastructure/identity/*`, the migrations under `backend/alembic/versions` for `identity.membership`):
   role, status (`active`/`revoked`), creation data, the link to the subject (`subject_id` UUID, not the
   `sub`), the studio, and what else references it (invitations, activity log, "last owner" count via
   `count_active_owners`).
2. **What the library store would have to carry** to replace it: `status`, `revision`, `attributes`; what it
   cannot (foreign keys to ARTISEVM tables, the `subject_id` surrogate, the `count_active_owners` query).
3. **RLS**: the membership table has a studio policy plus two "doors" (`app.subject_id`: a person reads
   their own memberships in every studio for `GET /me`; `app.invitation_token`). Could the library table
   carry the same policies, and who owns the migration (ARTISEVM's Alembic, since RLS and the app role are
   its)?
4. **Options**, each with cost, risk and rollback:
   - A. Keep the adapter (zero migration; the library store is for other apps). Recommended default.
   - B. Library table with ARTISEVM migrating data and dropping `identity.membership` (needs a
     backward-incompatible migration and its lock policy: `backend/alembic/lock_policy_allowlist.toml`).
   - C. Library table as the authority for the role only, ARTISEVM keeping a thin `membership` row for
     domain data (two writes per change: needs a transaction boundary and a reconciliation story).
5. **Recommendation** and the exact conditions under which the answer would flip (for example: a second
   application needs the same data; or DynamoDB becomes the production store).

## Acceptance criteria

- [ ] The ADR is written as **proposed**, with the three options and a recommendation, and the owner is told
  it needs a decision. No code, no migration.
- [ ] Every claim about ARTISEVM cites a file path; nothing is asserted from memory.
- [ ] The Resolution section of this issue links to the ADR number.
