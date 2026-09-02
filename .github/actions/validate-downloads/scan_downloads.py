#!/usr/bin/env python3
"""Scan changed .bes files' ActionScript for download URLs unknown to known_urls.txt.

Invoked by action.yml as a single step, with these environment variables:
    HEAD_SHA         - the pull request's head commit SHA
    FILES_LIST       - path to a NUL-separated list of changed file paths
    KNOWN_URLS_PATH  - path (relative to cwd) to the known-URL-pattern file,
                        read from whatever is already checked out (the PR
                        BASE, under this action's intended pull_request_target
                        caller - see action.yml's header for why that matters)
    MAX_BYTES        - per-file size cap before a file is skipped
    GITHUB_OUTPUT    - GitHub Actions' own output file

Every *.bes file named in FILES_LIST is read via `git show <HEAD_SHA>:<path>`
(never from the working tree, which under this action's intended caller holds
the PR base, not head) and treated purely as data: parsed as XML with
xml.etree.ElementTree, then each <ActionScript> body is scanned line-by-line
for a download command - see .github/actions/_lib/bes_downloads.py (shared
with validate-downloads-virustotal) for exactly what counts as one. See
action.yml for the full security rationale.

Exits 0 always - this script's effect is the `flagged` output and the warning
annotations it prints; action.yml decides what to do with them.
"""

import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "_lib"))
import bes_downloads as bd  # noqa: E402 - see sys.path.insert above

HEAD_SHA = os.environ["HEAD_SHA"]
FILES_LIST = os.environ["FILES_LIST"]
KNOWN_URLS_PATH = os.environ.get("KNOWN_URLS_PATH", "known_urls.txt")
MAX_BYTES = int(os.environ.get("MAX_BYTES", "10485760"))
GITHUB_OUTPUT = os.environ["GITHUB_OUTPUT"]

# --- Load known-URL patterns -------------------------------------------------

patterns = []
if os.path.isfile(KNOWN_URLS_PATH):
    with open(KNOWN_URLS_PATH, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                patterns.append(re.compile(line))
            except re.error as err:
                bd.warn(
                    f"ignoring invalid regex on line {lineno} of {KNOWN_URLS_PATH} "
                    f"({err}): {line}",
                    file=KNOWN_URLS_PATH,
                    line=lineno,
                )
else:
    bd.warn(
        f"{KNOWN_URLS_PATH} not found on the PR base; every download URL "
        "will be treated as unrecognized"
    )


def is_known(url):
    return any(p.fullmatch(url) for p in patterns)


# --- Main ---------------------------------------------------------------

with open(FILES_LIST, "rb") as fh:
    files = [p.decode("utf-8", errors="replace") for p in fh.read().split(b"\0") if p]

flagged = 0
checked = 0

for path in files:
    if not path.endswith(".bes"):
        continue
    checked += 1

    try:
        content = bd.read_git_show(HEAD_SHA, path)
    except subprocess.CalledProcessError as err:
        stderr = err.stderr.decode("utf-8", errors="replace")[:500]
        bd.warn(f"could not read PR-head content ({stderr}); skipping", file=path)
        continue

    if len(content) > MAX_BYTES:
        bd.warn(
            f"{len(content)} bytes exceeds the {MAX_BYTES} byte download-scan limit; skipping",
            file=path,
        )
        continue

    try:
        urls = list(bd.iter_bes_download_urls(content))
    except bd.ET.ParseError as err:
        # Not this check's job to fail on invalid XML - validate-content
        # (BES.xsd) already owns that; just skip so this check stays focused.
        bd.warn(f"not parseable BES XML ({err}); skipping", file=path)
        continue

    seen_in_file = set()
    for url in urls:
        if url in seen_in_file or is_known(url):
            continue
        seen_in_file.add(url)
        flagged += 1
        bd.warn(
            f'references a download URL that does not match any pattern in '
            f'{KNOWN_URLS_PATH}: "{url}". Please confirm this URL is legitimate, '
            f'then ask a maintainer to add a matching pattern to {KNOWN_URLS_PATH} '
            "before merging.",
            file=path,
            line=1,
        )

with open(GITHUB_OUTPUT, "a", encoding="utf-8") as fh:
    fh.write(f"flagged={flagged}\n")

print(f"Checked {checked} .bes file(s) under Sites/*/Fixlets; {flagged} unrecognized download URL(s) flagged.")
sys.exit(0)
