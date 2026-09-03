#!/usr/bin/env python3
"""Local test wrapper for .github/actions/validate-downloads/scan_downloads.py.

scan_downloads.py is wired for its GitHub Actions caller: it reads changed
files via `git show <HEAD_SHA>:<path>` (never the working tree) and writes a
`flagged` count to $GITHUB_OUTPUT. Neither fits an ad hoc local check against
files on disk, so this wrapper re-runs the same detection logic - imported
from .github/actions/_lib/bes_downloads.py, the module scan_downloads.py
itself uses, so this is exercising real production code, not a reimplementation
- directly against files you name with a glob, and prints results to stdout.

Note: scan_downloads.py itself never posts pull request comments either - it
only prints ::warning:: annotations and writes the output file; the PR label/
review steps live in action.yml. This wrapper keeps the same stdout
annotations, just sourced from disk instead of git history.

Usage:
    python dev/scan_downloads_local.py "Sites/TestSite/Fixlets/*.bes"
    python dev/scan_downloads_local.py "Sites/**/*.bes" --known-urls known_urls.txt
"""

import argparse
import glob
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / ".github" / "actions" / "_lib"))
import bes_downloads as bd  # noqa: E402 - see sys.path.insert above


def load_known_url_patterns(known_urls_path):
    import re

    patterns = []
    if known_urls_path.is_file():
        with open(known_urls_path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    patterns.append(re.compile(line))
                except re.error as err:
                    bd.warn(
                        f"ignoring invalid regex on line {lineno} of {known_urls_path} "
                        f"({err}): {line}",
                        file=str(known_urls_path),
                        line=lineno,
                    )
    else:
        bd.warn(f"{known_urls_path} not found; every download URL will be treated as unrecognized")
    return patterns


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "patterns",
        nargs="+",
        help='One or more glob patterns to scan, e.g. "Sites/TestSite/Fixlets/*.bes". '
        "Relative patterns are resolved against the repo root (%s)." % REPO_ROOT,
    )
    parser.add_argument(
        "--known-urls",
        default=str(REPO_ROOT / "known_urls.txt"),
        help="Path to the known-URL-pattern file (default: repo root known_urls.txt).",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=10 * 1024 * 1024,
        help="Per-file size cap before a file is skipped (default: 10 MiB).",
    )
    args = parser.parse_args()

    known_urls_path = pathlib.Path(args.known_urls)
    if not known_urls_path.is_absolute():
        known_urls_path = REPO_ROOT / known_urls_path
    patterns = load_known_url_patterns(known_urls_path)

    def is_known(url):
        return any(p.fullmatch(url) for p in patterns)

    files = []
    for pattern in args.patterns:
        pattern_path = pathlib.Path(pattern)
        resolved_pattern = pattern if pattern_path.is_absolute() else str(REPO_ROOT / pattern)
        matches = sorted(glob.glob(resolved_pattern, recursive=True))
        if not matches:
            bd.warn(f'glob pattern "{pattern}" matched no files')
        files.extend(matches)

    checked = 0
    flagged = 0

    for path in files:
        display_path = str(pathlib.Path(path).resolve().relative_to(REPO_ROOT).as_posix())

        if not path.endswith(".bes"):
            bd.warn("not a .bes file; skipping", file=display_path)
            continue
        checked += 1

        try:
            content = pathlib.Path(path).read_bytes()
        except OSError as err:
            bd.warn(f"could not read file ({err}); skipping", file=display_path)
            continue

        if len(content) > args.max_bytes:
            bd.warn(
                f"{len(content)} bytes exceeds the {args.max_bytes} byte download-scan limit; skipping",
                file=display_path,
            )
            continue

        try:
            urls = list(bd.iter_bes_download_urls(content))
        except bd.ET.ParseError as err:
            bd.warn(f"not parseable BES XML ({err}); skipping", file=display_path)
            continue

        seen_in_file = set()
        for url in urls:
            if url in seen_in_file or is_known(url):
                continue
            seen_in_file.add(url)
            flagged += 1
            bd.warn(
                f'references a download URL that does not match any pattern in '
                f'{known_urls_path.name}: "{url}". Please confirm this URL is legitimate, '
                f'then ask a maintainer to add a matching pattern to {known_urls_path.name} '
                "before merging.",
                file=display_path,
                line=1,
            )

    print(f"Checked {checked} .bes file(s); {flagged} unrecognized download URL(s) flagged.")
    sys.exit(0)


if __name__ == "__main__":
    main()
