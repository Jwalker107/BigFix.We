#!/usr/bin/env python3
"""Local test wrapper for
.github/actions/validate-downloads-virustotal/scan_and_submit.py.

scan_and_submit.py is wired for its GitHub Actions caller: it reads changed
files via `git show <HEAD_SHA>:<path>` (never the working tree), and writes
its rendered PR-comment Markdown + malicious/scanned/unresolved counts to
files ($COMMENT_BODY_PATH / $GITHUB_OUTPUT) that action.yml then uses to
post/update an actual pull request comment. None of that fits an ad hoc local
check against files on disk, so this wrapper:

  - finds download URLs the same way the real script does - importing
    .github/actions/_lib/bes_downloads.py, the module scan_and_submit.py
    itself uses, so URL discovery is exercising real production code - but
    reads the files directly from disk via a glob, instead of `git show`.
  - prints the rendered comment body and output values to stdout instead of
    writing them to a PR comment.

VirusTotal submission is real, costs quota (free tier: 4 requests/minute,
500/day), and needs a live API key, so it is NOT the default. Pass --submit
to actually call VirusTotal (reads VIRUSTOTAL_API_KEY from the environment -
never pass a key on the command line, where it would land in shell history).
Without --submit this only discovers and lists URLs - no network calls.

Usage:
    # Dry run: just show what URLs would be submitted, no VirusTotal calls.
    python dev/scan_and_submit_local.py "Sites/TestSite/Fixlets/*.bes"

    # Actually submit to VirusTotal (needs VIRUSTOTAL_API_KEY set):
    $env:VIRUSTOTAL_API_KEY = "<your key>"   # PowerShell
    python dev/scan_and_submit_local.py "Sites/TestSite/Fixlets/*.bes" --submit
"""

import argparse
import glob
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / ".github" / "actions" / "_lib"))
import bes_downloads as bd  # noqa: E402 - see sys.path.insert above

VT_BASE = "https://www.virustotal.com/api/v3"
SUBMIT_INTERVAL_SECONDS = 16
POLL_INTERVAL_SECONDS = 15
POLL_ATTEMPTS = 8  # ~2 minutes per URL
MAX_URLS_PER_RUN = 15
MAX_HTTP_RETRIES = 3


def fail(message):
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def vt_request(api_key, method, path, data=None):
    """Call one VirusTotal v3 endpoint; retries a 429 with exponential backoff."""
    url = f"{VT_BASE}{path}"
    body = None
    headers = {"x-apikey": api_key}
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    for attempt in range(1, MAX_HTTP_RETRIES + 1):
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            if err.code == 429 and attempt < MAX_HTTP_RETRIES:
                wait = 5 * (2**attempt)
                print(f"VirusTotal rate-limited (429); backing off {wait}s (attempt {attempt}/{MAX_HTTP_RETRIES})")
                time.sleep(wait)
                continue
            detail = err.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"HTTP {err.code}: {detail}") from err
        except urllib.error.URLError as err:
            raise RuntimeError(str(err.reason)) from err
    raise RuntimeError("exhausted retries")  # pragma: no cover - loop always returns or raises


def submit_url(api_key, url):
    resp = vt_request(api_key, "POST", "/urls", data={"url": url})
    return resp["data"]["id"]


def poll_analysis(api_key, analysis_id, poll_interval, poll_attempts):
    for _ in range(poll_attempts):
        resp = vt_request(api_key, "GET", f"/analyses/{analysis_id}")
        attrs = resp["data"]["attributes"]
        if attrs.get("status") == "completed":
            return attrs.get("stats", {})
        time.sleep(poll_interval)
    return None


def md_cell(text):
    """Escape a value for safe placement inside a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("`", "'")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "patterns",
        nargs="+",
        help='One or more glob patterns to scan, e.g. "Sites/TestSite/Fixlets/*.bes". '
        "Relative patterns are resolved against the repo root (%s)." % REPO_ROOT,
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=10 * 1024 * 1024,
        help="Per-file size cap before a file is skipped (default: 10 MiB).",
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        help="Actually submit discovered URLs to VirusTotal (costs quota; needs VIRUSTOTAL_API_KEY). "
        "Without this flag, URLs are only discovered and listed - no network calls.",
    )
    parser.add_argument(
        "--api-key-env",
        default="VIRUSTOTAL_API_KEY",
        help="Name of the environment variable holding the VirusTotal API key (default: VIRUSTOTAL_API_KEY). "
        "Never pass the key itself on the command line.",
    )
    parser.add_argument(
        "--max-urls",
        type=int,
        default=MAX_URLS_PER_RUN,
        help=f"Per-run cap on distinct URLs submitted (default: {MAX_URLS_PER_RUN}, matching production).",
    )
    parser.add_argument(
        "--submit-interval",
        type=float,
        default=SUBMIT_INTERVAL_SECONDS,
        help=f"Seconds to wait between submissions (default: {SUBMIT_INTERVAL_SECONDS}, matching VirusTotal's free-tier rate limit).",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=POLL_INTERVAL_SECONDS,
        help=f"Seconds to wait between analysis polls (default: {POLL_INTERVAL_SECONDS}).",
    )
    parser.add_argument(
        "--poll-attempts",
        type=int,
        default=POLL_ATTEMPTS,
        help=f"Max polls before giving up on one URL's analysis (default: {POLL_ATTEMPTS}).",
    )
    args = parser.parse_args()

    api_key = os.environ.get(args.api_key_env, "")
    if args.submit and not api_key:
        fail(
            f"--submit was given but ${args.api_key_env} is empty - set it first, e.g. (PowerShell) "
            f'$env:{args.api_key_env} = "<your key>"'
        )

    files = []
    for pattern in args.patterns:
        pattern_path = pathlib.Path(pattern)
        resolved_pattern = pattern if pattern_path.is_absolute() else str(REPO_ROOT / pattern)
        matches = sorted(glob.glob(resolved_pattern, recursive=True))
        if not matches:
            bd.warn(f'glob pattern "{pattern}" matched no files')
        files.extend(matches)

    # --- Gather distinct download URLs across every matched .bes file ------

    url_to_files = {}  # url -> set of display paths it was found in
    checked = 0
    read_failures = 0

    for path in files:
        if not path.endswith(".bes"):
            bd.warn("not a .bes file; skipping", file=path)
            continue
        checked += 1

        display_path = str(pathlib.Path(path).resolve().relative_to(REPO_ROOT).as_posix())

        try:
            content = pathlib.Path(path).read_bytes()
        except OSError as err:
            read_failures += 1
            bd.warn(f"could not read file ({err}); skipping", file=display_path)
            continue

        if len(content) > args.max_bytes:
            bd.warn(
                f"{len(content)} bytes exceeds the {args.max_bytes} byte scan limit; skipping",
                file=display_path,
            )
            continue

        try:
            urls = list(bd.iter_bes_download_urls(content))
        except bd.ET.ParseError as err:
            bd.warn(f"not parseable BES XML ({err}); skipping", file=display_path)
            continue

        for url in urls:
            url_to_files.setdefault(url, set()).add(display_path)

    if checked > 0 and read_failures == checked:
        fail(f"could not read any of the {checked} matched .bes file(s); see warnings above")

    all_urls = sorted(url_to_files)
    to_scan = all_urls[: args.max_urls]
    capped = all_urls[args.max_urls :]

    if capped:
        print(
            f"::warning::{len(capped)} download URL(s) were not scanned this run "
            f"(per-run cap of {args.max_urls}): " + ", ".join(capped)
        )

    if not args.submit:
        print(f"Checked {checked} .bes file(s); {len(all_urls)} distinct download URL(s) found (dry run - nothing submitted):")
        for url in all_urls:
            scanned_marker = "" if url in to_scan else " [would be capped]"
            print(f"  {url}{scanned_marker}")
            for f in sorted(url_to_files[url]):
                print(f"    <- {f}")
        print("\nRe-run with --submit (and VIRUSTOTAL_API_KEY set) to actually scan these with VirusTotal.")
        sys.exit(0)

    # --- Submit + poll each URL --------------------------------------------

    results = []  # each: {url, files, status, malicious, suspicious, harmless, undetected, detail}
    for i, url in enumerate(to_scan):
        if i > 0:
            time.sleep(args.submit_interval)

        entry = {"url": url, "files": sorted(url_to_files[url])}
        try:
            analysis_id = submit_url(api_key, url)
            stats = poll_analysis(api_key, analysis_id, args.poll_interval, args.poll_attempts)
            if stats is None:
                entry["status"] = "unresolved"
                entry["detail"] = "VirusTotal had not finished analyzing this URL within the wait budget"
            else:
                entry["status"] = "completed"
                entry["malicious"] = stats.get("malicious", 0)
                entry["suspicious"] = stats.get("suspicious", 0)
                entry["harmless"] = stats.get("harmless", 0)
                entry["undetected"] = stats.get("undetected", 0)
        except Exception as err:  # noqa: BLE001 - any VT/network failure becomes "unresolved", never a crash mid-scan
            entry["status"] = "unresolved"
            entry["detail"] = str(err)
        results.append(entry)
        print(f"{url}: {entry['status']}" + (f" (malicious={entry.get('malicious', 0)})" if entry["status"] == "completed" else ""))

    malicious_count = sum(1 for r in results if r["status"] == "completed" and r["malicious"] > 0)
    unresolved_count = sum(1 for r in results if r["status"] == "unresolved")

    # --- Render the same comment body as production, to stdout -------------

    lines = []
    if not all_urls:
        lines.append("# VirusTotal download scan")
        lines.append("")
        lines.append("> [!NOTE]")
        lines.append("> No download commands (prefetch/curl/wget/download) were found in the matched files.")
    elif malicious_count > 0:
        total_malicious_hits = sum(r.get("malicious", 0) for r in results)
        lines.append("# \U0001f6a8 VirusTotal scan: MALICIOUS DOWNLOAD DETECTED")
        lines.append("")
        lines.append("> [!CAUTION]")
        lines.append(
            f"> {total_malicious_hits} scanner(s) across {malicious_count} of {len(to_scan)} scanned "
            "download URL(s) were flagged as **malicious** by VirusTotal. Do not merge until a maintainer has reviewed this."
        )
    else:
        lines.append("# \u2705 VirusTotal scan: no malicious downloads detected")
        lines.append("")
        if unresolved_count:
            lines.append("> [!WARNING]")
            lines.append(
                f"> No scanner reported a malicious verdict, but {unresolved_count} of {len(to_scan)} "
                "download URL(s) could not be scanned (see table) - manual review recommended for those."
            )
        else:
            lines.append("> [!NOTE]")
            lines.append(f"> All {len(to_scan)} download URL(s) found were scanned by VirusTotal with no malicious verdicts.")

    if all_urls:
        lines.append("")
        lines.append("| URL | Referenced in | Malicious | Suspicious | Harmless | Undetected | Status |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in results:
            files_cell = "<br>".join(f"`{md_cell(f)}`" for f in r["files"])
            if r["status"] == "completed":
                mal = f"**{r['malicious']}**" if r["malicious"] > 0 else "0"
                row = (mal, r["suspicious"], r["harmless"], r["undetected"], "completed")
            else:
                row = ("-", "-", "-", "-", f"unresolved ({md_cell(r.get('detail', ''))})")
            lines.append(f"| `{md_cell(r['url'])}` | {files_cell} | {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} |")
        for url in capped:
            files_cell = "<br>".join(f"`{md_cell(f)}`" for f in sorted(url_to_files[url]))
            lines.append(f"| `{md_cell(url)}` | {files_cell} | - | - | - | - | not scanned (per-run cap) |")

    lines.append("")
    lines.append(
        f"Scanned {len(to_scan)} of {len(all_urls)} distinct download URL(s) found via VirusTotal's public API. "
        "Malicious/suspicious counts are the number of VirusTotal's third-party scan engines reporting that verdict, "
        "not a guarantee - review before trusting either a clean or a flagged result."
    )

    print("\n--- Rendered PR-comment body (would be posted/updated by action.yml) ---\n")
    print("\n".join(lines))
    print(f"\n--- Output values (would go to $GITHUB_OUTPUT) ---\nmalicious={malicious_count}\nscanned={len(to_scan)}\nunresolved={unresolved_count}")

    print(
        f"\nChecked {checked} .bes file(s); {len(all_urls)} distinct download URL(s) found, "
        f"{len(to_scan)} scanned, {malicious_count} flagged malicious, {unresolved_count} unresolved."
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
