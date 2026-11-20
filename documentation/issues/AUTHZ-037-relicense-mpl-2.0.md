# AUTHZ-037 · Relicense from MIT to MPL-2.0 (from 0.8.0)

Epic H · Size S · Depends on: none · Must land **in the 0.8.0 release**, not before

## Context

Decision (owner, 2026-11-14): the library must stay usable in commercial and closed applications without
restrictions, while anyone who modifies the library's own files must publish those modifications.
MPL-2.0 (file-level copyleft) does exactly that. Other options were considered and rejected: AGPL-3.0
(forces adopters' whole applications open), LGPL-3.0 (heavier conditions for no extra benefit in
Python), source-available licences such as BSL/PolyForm (not open source, deter adoption). No
open-source licence can forbid selling; MPL-2.0 only forces sharing the modified files.

Facts verified on 2026-11-14:

- `LICENSE` is MIT, "Copyright (c) 2024 Press Any Key". Decision (owner): the holder of the new `NOTICE`
  is **impalah <impalah@gmail.com>**.
- Versions up to and including **0.7.0 stay MIT for ever** (already on PyPI and in git history). Only
  releases from 0.8.0 carry MPL-2.0.
- All commits are by the owner (three author identities, to be confirmed as the same person) plus bots
  (`GitHub Action`, `dependabot`), so no third-party consent is needed. If anyone else contributes
  before 0.8.0, ask for their agreement first.
- Dependencies are MIT/BSD/Apache-2.0/ISC/MPL-2.0 plus optional/dev LGPL (`psycopg2-binary`, `pysonar`):
  compatible with MPL-2.0.
- No source file carries a licence header; there is no `NOTICE`.

## Do not do it earlier

`main` currently describes 0.7.0, published under MIT. Changing `LICENSE` on `main` before the 0.8.0
release would put an MPL file next to MIT metadata on PyPI. Do this issue as part of the 0.8.0
release commit (together with AUTHZ-036), or in a dedicated commit **immediately before** the version
bump.

## Scope

1. `LICENSE`: replace with the unmodified MPL-2.0 text (https://www.mozilla.org/MPL/2.0/) and keep the
   copyright holder line in a new `NOTICE` (`Copyright (c) 2024-2026 impalah <impalah@gmail.com>`; this makes the address public in the
   repository and on PyPI, as the git history already does).
2. `pyproject.toml`:
   - line 9 `license = {text = "MIT"}` -> `license = "MPL-2.0"` (SPDX expression) and
     `license-files = ["LICENSE", "NOTICE"]`, **only if the build backend supports PEP 639**
     (setuptools >= 77, hatchling >= 1.27, uv_build; this project uses unpinned `hatchling`, so the
     current one qualifies: verify with `uv build`); otherwise `license = {text = "MPL-2.0"}`.
   - line 14 classifier `License :: OSI Approved :: MIT License` -> `License :: OSI Approved ::
     Mozilla Public License 2.0 (MPL 2.0)` (drop it when using the SPDX expression: PEP 639 forbids both).
3. `README.md`: badge on line 5 and the "MIT — see LICENSE" section (line ~476); explain in two lines what
   MPL-2.0 means for users ("use it freely, also in closed commercial applications; changes to the
   library's own files must be published under MPL-2.0").
4. `pages_source/index.rst`: badge on line 19; add a short "Licence" section; regenerate `docs/` only in
   the release (`make docs`).
5. `documentation/CHANGELOG.txt`, entry 0.8.0, **Upgrade notes**: "Licence changed from MIT to MPL-2.0.
   Releases up to 0.7.0 remain MIT. Using the library from closed or commercial applications is
   unchanged; only modifications of the library's own files must be shared."
6. Source headers (optional, recommended): `# SPDX-License-Identifier: MPL-2.0` as the first line of each
   file under `src/auth_middleware/` through a one-off script; add a ruff or pre-commit check so new
   files get it. MPL-2.0 does not require headers, but they make file-level scope unambiguous.
7. CLAUDE.md / memory: nothing about the licence there; no change.

## On GitHub (manual, owner)

- The licence shown in the repository sidebar is detected from `LICENSE`: after pushing it updates
  by itself (it can take a few minutes).
- Nothing in the repository settings sets the licence; there is no field to change.
- Create the GitHub Release 0.8.0 notes with the licence change at the top.
- Optional: pin a note in the README or a Discussion announcing it.
- If you register the name `auth-middleware` as a trademark, add a `TRADEMARKS.md` (the licence grants
  no trademark rights; MPL-2.0 section 2.3 already excludes them).

## Acceptance criteria

- [ ] `LICENSE` is byte-identical to the official MPL-2.0 text.
- [ ] `uv build` produces sdist and wheel whose METADATA says `License-Expression: MPL-2.0` (or the
  classifier) and which include `LICENSE`; `twine check dist/*` passes.
- [ ] `grep -ri "MIT" README.md pyproject.toml pages_source/index.rst` finds no remaining licence
  reference (other than historical CHANGELOG lines).
- [ ] CHANGELOG 0.8.0 carries the upgrade note; 0.7.0 entry is untouched.
- [ ] No version bump in this issue (it is part of the release flow: `make bump-version PART=minor`).
- [ ] `make check` and the test suite pass.

## Out of scope

Trademark registration, a commercial dual licence, CLA/DCO for future contributors (consider a DCO
sign-off requirement if outside contributions start).
