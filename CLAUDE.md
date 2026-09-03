# BigFix Community Content — Notes for Claude

This repo holds BigFix community content organized as BES Support site propagation conventions (see `README.md`), plus a GitHub Pages viewer for browsing it (`index.html`, `docs/app.js`, `docs/style.css`, `docs/index.json`, `scripts/generate_index.py`).

- **`Sites/<SiteName>/Fixlets/`**: `.bes` files (Fixlets/Tasks/Analyses), directly in `Fixlets/` or in any subdirectory beneath it (e.g. `Sites/BigFix Management/Fixlets/Tasks/Foo.bes`).
- **`Sites/<SiteName>/NonClientFiles/`** and **`Sites/<SiteName>/OtherFiles/`**: server-side/non-client site artifacts - not `.bes` content, not automatically validated.
- **`Signatures/`**: BigFix Inventory Signature `.xml` files, directly in that top-level directory (not nested in a subdirectory).

## Automated CI checks

Only `Sites/*/Fixlets/**` and `Signatures/*` (direct children only, not nested) get automated content validation; anything else changed in a PR is flagged for mandatory human review instead. Keep this list in sync with `README.md`'s "Content Validation Automation" section if either changes again.

- **Schema/filename validation** (`.github/workflows/schema-validation-pull-request.yml`, plain `pull_request` - read-only token, runs even against fork PRs): `.github/actions/validate-new-content-filenames` (any newly-added `.bes` file, anywhere in the repo, must start with a letter - digits are reserved for the auto-assigned content-ID prefix), `.github/actions/validate-content` (`Sites/*/Fixlets/**` against `scripts/BES.xsd`), `.github/actions/validate-signatures` (`Signatures/*` against `scripts/signature.xsd`).
- **Download-URL checks** (`pull_request_target` - needs a write token to label/comment/review, so the checkout is deliberately pinned to the PR base, never the PR's own tree - see each action's own header comment): `.github/actions/validate-downloads` (`.github/workflows/validate-downloads.yml`) flags any download command (`prefetch`, `add prefetch item`/`add nohash prefetch item`, `download`/`download now`, `curl`, `wget`) in a Fixlet/Task's `<ActionScript>` whose URL doesn't match a pattern in the repo-root `known_urls.txt` (read from the PR base, so a PR can't add its own allow-pattern to self-approve) with the `new-download-url` label + a requested-changes review. `.github/actions/validate-downloads-virustotal` (`.github/workflows/validate-downloads-virustotal.yml`) submits every download URL found (not just unrecognized ones) to VirusTotal and posts/updates one PR status comment with the results, additionally labeling `virustotal-flagged` + requesting changes if any engine reports a URL malicious. Both trigger on any PR touching `Sites/**` and share the URL-detection logic in `.github/actions/_lib/bes_downloads.py` - change behavior there, not in either action's own script, so the two checks can't drift apart.
- **Out-of-scope flag** (`.github/actions/flag-out-of-scope-changes`, `.github/workflows/flag-out-of-scope-changes.yml`, `pull_request_target`): anything changed outside `Sites/*/Fixlets/**` or `Signatures/*` gets the `needs-manual-review` label + a requested-changes review (with one narrow exception for a `scripts/contentid.json` "nextid"-only bump - see the action's own header).
- **Secret scanning** (`.github/workflows/trufflehog-secrets-scan.yml`): TruffleHog scans every push to `main` and every pull request for verified/live secrets.
- **pre-commit** (`.github/actions/run-pre-commit-autofix`, `.github/workflows/pre-commit-autofix.yml`, plain `pull_request`): runs the hooks pinned in `.pre-commit-config.yaml` (generic whitespace/YAML/large-file checks, the `jgstew/pre-commit-bigfix` BigFix-convention/ActionScript-lint/prefetch/script hooks, and a Trivy filesystem/config scan) against every changed file in a same-repo PR, auto-fixing what it can and pushing a `[bot]` commit; a fork PR gets a log notice instead (GitHub Actions can never push to a fork's branch). Note: `scripts/pre_commit_bigfix/` and `scripts/requirements.txt` are a leftover vendored copy from this repo's sibling project (`bigfix.we`, which uses a `content/` layout) - nothing in this repo's actions or workflows actually reads them; the real hook code comes straight from the pinned `jgstew/pre-commit-bigfix` repo/rev in `.pre-commit-config.yaml`.
- **Post-merge** (`.github/workflows/update-index.yml`, runs on push to `main`): assigns a numeric content-ID prefix to any new `.bes` file under `Sites/*/Fixlets/**` (unless the merged PR carried the `keep-content-ids` label) and regenerates `docs/index.json` for the GitHub Pages viewer.

## GitHub Pages viewer

Before touching any part of the viewer — `docs/app.js`, `docs/style.css`, `scripts/generate_index.py`, `index.html`, or `.github/workflows/update-index.yml` — read the design notes and lessons learned below in full. They cover the architecture (why content is fetched same-origin with no GitHub API/auth involved), the index-generation/frontmatter format shared with `app.js`, the sidebar tree and Signature-rendering implementation, the description HTML sanitizer, functionality that was deliberately removed (don't resurrect it without a reason), and how to verify UI changes headlessly in this environment.

@dev/GithubPagesViewerNotes.md

## Other references

- `scripts/signature-schema.md` — the BigFix Inventory Signature XML format (frontmatter comment fields + `SoftwareIdentityCatalog` schema), authoritative for anything Signature-related.
- `README.md` — repo purpose and content organization conventions.
- `CONTRIBUTING.md` — contribution guidelines.
