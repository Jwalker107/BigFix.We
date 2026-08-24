# BigFix Community Content — Notes for Claude

This repo holds BigFix community content organized as BES Support site propagation conventions (see `README.md`), plus a GitHub Pages viewer for browsing it (`index.html`, `docs/app.js`, `docs/style.css`, `docs/index.json`, `scripts/generate_index.py`).

- **`Sites/<SiteName>/Fixlets/`**: `.bes` files (Fixlets/Tasks/Analyses), directly in `Fixlets/` or in any subdirectory beneath it (e.g. `Sites/BigFix Management/Fixlets/Tasks/Foo.bes`).
- **`Sites/<SiteName>/NonClientFiles/`** and **`Sites/<SiteName>/OtherFiles/`**: server-side/non-client site artifacts - not `.bes` content, not automatically validated.
- **`Signatures/`**: BigFix Inventory Signature `.xml` files, directly in that top-level directory (not nested in a subdirectory).

Only `Sites/*/Fixlets/**` and `Signatures/` have automated CI validation (`.github/actions/validate-content`, `validate-signatures`, `validate-content-conventions`, orchestrated by `.github/workflows/validate-pull-request.yml`); anything else changed in a PR is flagged for mandatory human review by `.github/actions/flag-out-of-scope-changes` (`.github/workflows/flag-out-of-scope-changes.yml`). Keep these paths in sync with `README.md` if the structure changes again.

Before touching any part of the viewer — `docs/app.js`, `docs/style.css`, `scripts/generate_index.py`, `index.html`, or `.github/workflows/update-index.yml` — read the design notes and lessons learned below in full. They cover the architecture (why content is fetched same-origin with no GitHub API/auth involved), the index-generation/frontmatter format shared with `app.js`, the sidebar tree and Signature-rendering implementation, the description HTML sanitizer, functionality that was deliberately removed (don't resurrect it without a reason), and how to verify UI changes headlessly in this environment.

@dev/GithubPagesViewerNotes.md

## Other references

- `dev/scripts/signature-schema.md` — the BigFix Inventory Signature XML format (frontmatter comment fields + `SoftwareIdentityCatalog` schema), authoritative for anything Signature-related.
- `README.md` — repo purpose and content organization conventions.
- `CONTRIBUTING.md` — contribution guidelines.
