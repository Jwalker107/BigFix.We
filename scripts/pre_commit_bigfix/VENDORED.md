# Vendored from pre-commit-bigfix

> **Status in this repo: not currently used by anything.** This directory (and
> `../requirements.txt`) was carried over from this repo's sibling project
> (`bigfix.we`, which organizes content under `content/Analysis|Fixlet|Task/`
> and runs a `.github/workflows/validate-content-conventions.yml` that reads
> this exact vendored copy by commit SHA at PR time). **This repo
> (`Jason-BigFix.We`) organizes content under `Sites/*/Fixlets/**` instead, and
> has no `validate-content-conventions.yml` workflow** - nothing in
> `.github/actions` or `.github/workflows` here reads any file in this
> directory. The same three hooks documented below DO still run in this
> repo's CI and via local `pre-commit` - see `.github/actions/run-pre-commit-autofix`
> / `.github/workflows/pre-commit-autofix.yml` - but they run the normal
> pre-commit way, straight from the `jgstew/pre-commit-bigfix` repo/rev pinned
> in `../../.pre-commit-config.yaml`, not from this local copy. Keeping this
> directory around is harmless (pre-commit's own hook resolution never looks
> here), but it's dead weight - safe to delete along with `../requirements.txt`
> if a maintainer confirms it's not wanted for some other reason.

This directory is a partial, **unmodified** copy of the `pre_commit_bigfix`
Python package from:

- Source: https://github.com/jgstew/pre-commit-bigfix
- Vendored at commit: `a6823f831ad9f0ff2e7d9738a955e52aaf7866b9` (2026-08-16)
- Package version: `0.6.1` (see `__init__.py`)
- License: MIT — see `../LICENSE-pre-commit-bigfix.txt`

## What's here and why (as designed for `bigfix.we`, not read by anything here)

Only the files needed to run three of that project's pre-commit hooks were
vendored — the ones `bigfix.we`'s `.github/workflows/validate-content-conventions.yml`
runs against every `content/Analysis|Fixlet|Task/**/*.bes` file added or
modified in a pull request:

| File | Hook it implements | Purpose |
|---|---|---|
| `bes_conventions_check.py` | `bes-conventions-check` | Opinionated BES content conventions (date/CVE/CPE formats, CDATA usage, Title/Description placeholders, ...) that BES.xsd can't express |
| `bes_actionscript_lint_schclass.py` | `bes-actionscript-lint-schclass` | Lints `<ActionScript>` bodies against the BigFix console's own lexical grammar |
| `bes_actionscript_validate_prefetch.py` | `bes-actionscript-validate-prefetch` | Validates `prefetch` / `add prefetch item` lines via the `bigfix_prefetch` package |
| `schclass.py`, `schclass_tokenizer.py`, `schclass_data/*.schclass` | (dependencies of the lint-schclass hook above) | Loader + tokenizer for the vendored `.schclass` lexer-grammar files |
| `__init__.py` | — | Makes this importable as the `pre_commit_bigfix` package, unchanged from upstream (own version string) |

**Not vendored:** `bes_schema_validate.py` (its own hook, `bes-schema-validate`)
was deliberately left out of the original `bigfix.we` vendoring — that repo
already validates BES XML against its own `BES.xsd` directly with `xmllint`,
so pulling in its `validate_bes_xml` dependency there would be redundant. (This
repo's own equivalent is `.github/actions/validate-content`, for the same
reason.)

Every file above is byte-for-byte what upstream ships — nothing here has been
edited. Read each module's own docstring for what it checks, its exit codes,
its CLI flags, and its file-level opt-out comment markers (e.g.
`<!-- pre-commit-skip: bes-conventions-check -->`).

## Why `bigfix.we` vendors instead of `pip install pre-commit-bigfix`

That repo's PR-time workflow needs the checker **code itself** to come from
its own trusted history (specifically, the pull request's *base* commit), not
from PyPI at whatever version happens to be latest when a job runs, and not
from the pull request under test. A CI-triggering PR modifying `content/**`
can never modify the copy of these scripts that grades it, which is the whole
point. This repo doesn't have that PR-time workflow at all - here, the same
trust property comes from `.pre-commit-config.yaml` itself being read from the
PR base (see `.github/actions/run-pre-commit-autofix`'s own header), with
pre-commit fetching the pinned hook repo fresh rather than trusting a local
copy - so there was never a reason to vendor here in the first place.

## How to refresh this vendored copy (only relevant if this ever gets wired up)

1. Pull the latest `pre-commit-bigfix` source and re-copy the files listed in
   the table above into this directory, overwriting what's here.
2. Update the "Vendored at commit" / "Package version" lines above.
3. Diff `../requirements.txt` against upstream's `setup.cfg`
   `[options] install_requires` for the three hooks above (currently `lxml`
   and `bigfix_prefetch>=1.1.5`) and update if upstream's pins changed.
4. Since nothing in this repo currently exercises this vendored copy, there is
   no existing job to re-run as a check - if you do wire it up, add one before
   relying on it.
