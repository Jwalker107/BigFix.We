# BigFix Community Content — Notes for Claude

This repo holds BigFix community content under `content/` (Fixlets/Tasks/Analyses/Baselines as `.bes`, Inventory Signatures as `.xml`) plus a GitHub Pages viewer for browsing it (`index.html`, `docs/app.js`, `docs/style.css`, `docs/index.json`, `scripts/generate_index.py`).

Before touching any part of the viewer — `docs/app.js`, `docs/style.css`, `scripts/generate_index.py`, `index.html`, or `.github/workflows/update-index.yml` — read the design notes and lessons learned below in full. They cover the architecture (why content is fetched same-origin with no GitHub API/auth involved), the index-generation/frontmatter format shared with `app.js`, the sidebar tree and Signature-rendering implementation, the description HTML sanitizer, functionality that was deliberately removed (don't resurrect it without a reason), and how to verify UI changes headlessly in this environment.

@dev/GithubPagesViewerNotes.md

## Other references

- `dev/scripts/signature-schema.md` — the BigFix Inventory Signature XML format (frontmatter comment fields + `SoftwareIdentityCatalog` schema), authoritative for anything Signature-related.
- `README.md` — repo purpose and content organization conventions.
- `CONTRIBUTING.md` — contribution guidelines.
