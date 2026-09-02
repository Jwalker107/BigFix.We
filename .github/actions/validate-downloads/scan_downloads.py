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
for a download command. See action.yml for the full security rationale.

Exits 0 always - this script's effect is the `flagged` output and the warning
annotations it prints; action.yml decides what to do with them.
"""

import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

HEAD_SHA = os.environ["HEAD_SHA"]
FILES_LIST = os.environ["FILES_LIST"]
KNOWN_URLS_PATH = os.environ.get("KNOWN_URLS_PATH", "known_urls.txt")
MAX_BYTES = int(os.environ.get("MAX_BYTES", "10485760"))
GITHUB_OUTPUT = os.environ["GITHUB_OUTPUT"]

# Per GitHub's documented `::workflow-command::` escaping rules
# (actions/toolkit's core/src/command.ts: escapeProperty/escapeData): order
# matters - '%' must be escaped first, or the '%' introduced by the other
# substitutions would itself get re-escaped.


def escape_property(s):
    s = s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    s = s.replace(":", "%3A").replace(",", "%2C")
    return s


def escape_data(s):
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def warn(message, file=None, line=None):
    props = []
    if file is not None:
        props.append(f"file={escape_property(file)}")
    if line is not None:
        props.append(f"line={line}")
    prefix = f"::warning {','.join(props)}::" if props else "::warning::"
    print(f"{prefix}{escape_data(message)}")


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
                warn(
                    f"ignoring invalid regex on line {lineno} of {KNOWN_URLS_PATH} "
                    f"({err}): {line}",
                    file=KNOWN_URLS_PATH,
                    line=lineno,
                )
else:
    warn(
        f"{KNOWN_URLS_PATH} not found on the PR base; every download URL "
        "will be treated as unrecognized"
    )


def is_known(url):
    return any(p.fullmatch(url) for p in patterns)


# --- ActionScript scanning ---------------------------------------------------

# A generic absolute-URI token: scheme://rest-with-no-whitespace-or-quoting.
URL_RE = re.compile(r"""[A-Za-z][A-Za-z0-9+.\-]*://[^\s"'<>]+""")


def clean_url(u):
    """Strip trailing punctuation a URL token likely picked up from prose/syntax."""
    return u.rstrip(").,;:'\"")


# BigFix's own download syntax ("prefetch ...", "add prefetch item ...",
# "add nohash prefetch item ...") plus "download"/"download now" and the two
# third-party downloaders BigFix content commonly shells out to.
DOWNLOAD_KEYWORDS_RE = re.compile(r"\bdownload(\s+now)?\b|\bcurl\b|\bwget\b", re.IGNORECASE)


def is_download_line(lowered_stripped):
    if "prefetch item" in lowered_stripped:  # covers both add/add nohash forms
        return True
    if lowered_stripped.startswith("prefetch "):
        return True
    return bool(DOWNLOAD_KEYWORDS_RE.search(lowered_stripped))


# The raw content of a `createfile until <MARKER>` block is file text being
# written out, not ActionScript commands - a prefetch/curl/wget-looking line
# in there isn't a command at all, so lines between the two markers are
# skipped, same judgement bes_actionscript_validate_prefetch.py makes.
HEREDOC_START_RE = re.compile(r"^createfile\s+until\s+(\S+)\s*$", re.IGNORECASE)


def find_download_urls(actionscript_text):
    """Yield URLs from download-command lines in one ActionScript body."""
    heredoc_end = None
    for raw_line in actionscript_text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = raw_line.strip()
        if heredoc_end is not None:
            if stripped == heredoc_end:
                heredoc_end = None
            continue
        start = HEREDOC_START_RE.match(stripped)
        if start:
            heredoc_end = start.group(1)
            continue
        if not stripped or stripped.startswith("//"):
            continue
        if not is_download_line(stripped.lower()):
            continue
        for match in URL_RE.findall(stripped):
            yield clean_url(match)


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
        result = subprocess.run(
            ["git", "show", f"{HEAD_SHA}:{path}"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as err:
        stderr = err.stderr.decode("utf-8", errors="replace")[:500]
        warn(f"could not read PR-head content ({stderr}); skipping", file=path)
        continue
    content = result.stdout

    if len(content) > MAX_BYTES:
        warn(
            f"{len(content)} bytes exceeds the {MAX_BYTES} byte download-scan limit; skipping",
            file=path,
        )
        continue

    try:
        root = ET.fromstring(content)
    except ET.ParseError as err:
        # Not this check's job to fail on invalid XML - validate-content
        # (BES.xsd) already owns that; just skip so this check stays focused.
        warn(f"not parseable BES XML ({err}); skipping", file=path)
        continue

    seen_in_file = set()
    for element in root.iter("ActionScript"):
        for url in find_download_urls(element.text or ""):
            if url in seen_in_file or is_known(url):
                continue
            seen_in_file.add(url)
            flagged += 1
            warn(
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
