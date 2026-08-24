# Vendored from pre-commit-bigfix

This directory is a partial, **unmodified** copy of the `pre_commit_bigfix`
Python package from:

- Source: https://github.com/jgstew/pre-commit-bigfix
- Vendored at commit: `a6823f831ad9f0ff2e7d9738a955e52aaf7866b9` (2026-08-16)
- Package version: `0.6.1` (see `__init__.py`)
- License: MIT — see `../LICENSE-pre-commit-bigfix.txt`

## What's here and why

Only the files needed to run three of that project's pre-commit hooks are
vendored — the ones `.github/workflows/validate-content-conventions.yml` runs
against every `content/Analysis|Fixlet|Task/**/*.bes` file added or modified in
a pull request:

| File | Hook it implements | Purpose |
|---|---|---|
| `bes_conventions_check.py` | `bes-conventions-check` | Opinionated BES content conventions (date/CVE/CPE formats, CDATA usage, Title/Description placeholders, ...) that BES.xsd can't express |
| `bes_actionscript_lint_schclass.py` | `bes-actionscript-lint-schclass` | Lints `<ActionScript>` bodies against the BigFix console's own lexical grammar |
| `bes_actionscript_validate_prefetch.py` | `bes-actionscript-validate-prefetch` | Validates `prefetch` / `add prefetch item` lines via the `bigfix_prefetch` package |
| `schclass.py`, `schclass_tokenizer.py`, `schclass_data/*.schclass` | (dependencies of the lint-schclass hook above) | Loader + tokenizer for the vendored `.schclass` lexer-grammar files |
| `__init__.py` | — | Makes this importable as the `pre_commit_bigfix` package, unchanged from upstream (own version string) |

**Not vendored:** `bes_schema_validate.py` (its own hook, `bes-schema-validate`)
was deliberately left out — this repo already validates BES XML against
`scripts/BES.xsd` directly with `xmllint` in
`.github/workflows/validate-content.yml`, so pulling in its `validate_bes_xml`
dependency here would be redundant.

Every file above is byte-for-byte what upstream ships — nothing here has been
edited. Read each module's own docstring for what it checks, its exit codes,
its CLI flags, and its file-level opt-out comment markers (e.g.
`<!-- pre-commit-skip: bes-conventions-check -->`).

## Why vendor instead of `pip install pre-commit-bigfix`

The workflow that runs these needs the checker **code itself** to come from
this repo's own trusted history (specifically, the pull request's *base*
commit — see the security note at the top of
`validate-content-conventions.yml`), not from PyPI at whatever version happens
to be latest when a job runs, and not from the pull request under test. A
CI-triggering PR modifying `content/**` can never modify the copy of these
scripts that grades it, which is the whole point.

## How to refresh this vendored copy

1. Pull the latest `pre-commit-bigfix` source and re-copy the files listed in
   the table above into this directory, overwriting what's here.
2. Update the "Vendored at commit" / "Package version" lines above.
3. Diff `../requirements.txt` against upstream's `setup.cfg`
   `[options] install_requires` for the three hooks above (currently `lxml`
   and `bigfix_prefetch>=1.1.5`) and update if upstream's pins changed.
4. Re-run `.github/workflows/validate-content-conventions.yml` (or the
   equivalent commands locally — see that workflow file) against a few real
   `content/` files before merging, since these are unmodified upstream
   sources this repo doesn't otherwise exercise.
