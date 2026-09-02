#!/usr/bin/env python3
"""Submit every download URL in a pull request's changed .bes files to VirusTotal.

Invoked by action.yml as a single step, with these environment variables:
    HEAD_SHA             - the pull request's head commit SHA
    FILES_LIST           - path to a NUL-separated list of changed file paths
    MAX_BYTES            - per-file size cap before a file is skipped
    VIRUSTOTAL_API_KEY   - VirusTotal public API key (repo secret)
    COMMENT_BODY_PATH    - where to write the rendered Markdown PR-comment body
    GITHUB_OUTPUT        - GitHub Actions' own output file

URL discovery reuses .github/actions/_lib/bes_downloads.py - the exact same
extraction used by validate-downloads, so "what counts as a download command"
never drifts between the two checks. Every distinct URL found (deduplicated,
case-sensitive) across every changed *.bes file is submitted to VirusTotal's
public API (POST /urls), then polled (GET /analyses/{id}) until VirusTotal
reports a verdict or this script gives up waiting.

Rate limiting: the public API allows 4 requests/minute and 500/day. This
script throttles submissions to stay under that, retries a 429 with backoff,
and caps how many distinct URLs one run will submit (MAX_URLS_PER_RUN) so a
pull request naming an unusually large number of download URLs can't exhaust
the day's quota or make one run unreasonably slow - any URL beyond the cap is
named in the PR comment as "not scanned" rather than silently dropped.

Writes COMMENT_BODY_PATH with the full PR-comment Markdown (including a
hidden HTML marker action.yml uses to find and update a prior run's comment
instead of piling up a new one every push), and sets these GITHUB_OUTPUT
values for action.yml to act on:
    malicious   - count of scanned URLs with at least one VirusTotal engine
                  reporting them malicious (drives the label + REQUEST_CHANGES)
    scanned     - count of URLs actually submitted this run
    unresolved  - count of URLs that timed out or errored (no verdict reached)

Exits 0 unless VIRUSTOTAL_API_KEY is missing/empty, or no *.bes file in
FILES_LIST could be read at all - those are genuine setup problems, not a
"some URLs were flagged" outcome, and should show as a failed job so they get
noticed.
"""

import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "_lib"))
import bes_downloads as bd  # noqa: E402 - see sys.path.insert above

HEAD_SHA = os.environ["HEAD_SHA"]
FILES_LIST = os.environ["FILES_LIST"]
MAX_BYTES = int(os.environ.get("MAX_BYTES", "10485760"))
API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
COMMENT_BODY_PATH = os.environ["COMMENT_BODY_PATH"]
GITHUB_OUTPUT = os.environ["GITHUB_OUTPUT"]

COMMENT_MARKER = "<!-- validate-downloads-virustotal:status -->"

VT_BASE = "https://www.virustotal.com/api/v3"
# Free-tier VirusTotal API limits: 4 requests/minute, 500/day, no batch
# endpoint. SUBMIT_INTERVAL keeps submissions at 60/4 = 15s apart with a
# small safety margin; POLL_INTERVAL/POLL_ATTEMPTS bound how long this script
# waits for one URL's analysis to finish before treating it as unresolved.
SUBMIT_INTERVAL_SECONDS = 16
POLL_INTERVAL_SECONDS = 15
POLL_ATTEMPTS = 8  # ~2 minutes per URL
MAX_URLS_PER_RUN = 15
MAX_HTTP_RETRIES = 3


def fail(message):
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


if not API_KEY:
    fail(
        "VIRUSTOTAL_API_KEY is empty - add it as a repository secret "
        "(Settings > Secrets and variables > Actions) before this check can run."
    )


# --- VirusTotal API -----------------------------------------------------


def vt_request(method, path, data=None):
    """Call one VirusTotal v3 endpoint; retries a 429 with exponential backoff."""
    url = f"{VT_BASE}{path}"
    body = None
    headers = {"x-apikey": API_KEY}
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


def submit_url(url):
    """Submit `url` for analysis; return its analysis id."""
    resp = vt_request("POST", "/urls", data={"url": url})
    return resp["data"]["id"]


def poll_analysis(analysis_id):
    """Poll an analysis until VirusTotal completes it; return its stats dict, or None on timeout."""
    for _ in range(POLL_ATTEMPTS):
        resp = vt_request("GET", f"/analyses/{analysis_id}")
        attrs = resp["data"]["attributes"]
        if attrs.get("status") == "completed":
            return attrs.get("stats", {})
        time.sleep(POLL_INTERVAL_SECONDS)
    return None


# --- Gather distinct download URLs across every changed .bes file ----------

with open(FILES_LIST, "rb") as fh:
    files = [p.decode("utf-8", errors="replace") for p in fh.read().split(b"\0") if p]

url_to_files = {}  # url -> set of file paths it was found in
checked = 0
read_failures = 0

for path in files:
    if not path.endswith(".bes"):
        continue
    checked += 1

    try:
        content = bd.read_git_show(HEAD_SHA, path)
    except subprocess.CalledProcessError as err:
        read_failures += 1
        stderr = err.stderr.decode("utf-8", errors="replace")[:500]
        bd.warn(f"could not read PR-head content ({stderr}); skipping", file=path)
        continue

    if len(content) > MAX_BYTES:
        bd.warn(
            f"{len(content)} bytes exceeds the {MAX_BYTES} byte scan limit; skipping",
            file=path,
        )
        continue

    try:
        urls = list(bd.iter_bes_download_urls(content))
    except bd.ET.ParseError as err:
        bd.warn(f"not parseable BES XML ({err}); skipping", file=path)
        continue

    for url in urls:
        url_to_files.setdefault(url, set()).add(path)

if checked > 0 and read_failures == checked:
    fail(f"could not read any of the {checked} changed .bes file(s) at {HEAD_SHA}; see warnings above")

all_urls = sorted(url_to_files)
to_scan = all_urls[:MAX_URLS_PER_RUN]
capped = all_urls[MAX_URLS_PER_RUN:]

if capped:
    print(
        f"::warning::{len(capped)} download URL(s) were not scanned this run "
        f"(per-run cap of {MAX_URLS_PER_RUN}, to stay within VirusTotal's free-tier "
        "daily quota): " + ", ".join(capped)
    )

# --- Submit + poll each URL ---------------------------------------------

results = []  # each: {url, files, status, malicious, suspicious, harmless, undetected, detail}
for i, url in enumerate(to_scan):
    if i > 0:
        time.sleep(SUBMIT_INTERVAL_SECONDS)

    entry = {"url": url, "files": sorted(url_to_files[url])}
    try:
        analysis_id = submit_url(url)
        stats = poll_analysis(analysis_id)
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

# --- Render the PR comment ------------------------------------------------


def md_cell(text):
    """Escape a value for safe placement inside a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("`", "'")


lines = [COMMENT_MARKER]

if not all_urls:
    lines.append("# VirusTotal download scan")
    lines.append("")
    lines.append("> [!NOTE]")
    lines.append("> No download commands (prefetch/curl/wget/download) were found in this pull request's changed Fixlets/Tasks.")
elif malicious_count > 0:
    total_malicious_hits = sum(r.get("malicious", 0) for r in results)
    lines.append("# 🚨 VirusTotal scan: MALICIOUS DOWNLOAD DETECTED")
    lines.append("")
    lines.append("> [!CAUTION]")
    lines.append(
        f"> {total_malicious_hits} scanner(s) across {malicious_count} of {len(to_scan)} scanned "
        "download URL(s) in this pull request were flagged as **malicious** by VirusTotal. "
        "Do not merge until a maintainer has reviewed this."
    )
else:
    lines.append("# ✅ VirusTotal scan: no malicious downloads detected")
    lines.append("")
    if unresolved_count:
        lines.append("> [!WARNING]")
        lines.append(
            f"> No scanner reported a malicious verdict, but {unresolved_count} of {len(to_scan)} "
            "download URL(s) could not be scanned (see table) - manual review recommended for those."
        )
    else:
        lines.append("> [!NOTE]")
        lines.append(f"> All {len(to_scan)} download URL(s) found in this pull request were scanned by VirusTotal with no malicious verdicts.")

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
    f"<sub>Scanned {len(to_scan)} of {len(all_urls)} distinct download URL(s) found via VirusTotal's public API. "
    "Malicious/suspicious counts are the number of VirusTotal's third-party scan engines reporting that verdict, "
    "not a guarantee - review before trusting either a clean or a flagged result.</sub>"
)

with open(COMMENT_BODY_PATH, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")

with open(GITHUB_OUTPUT, "a", encoding="utf-8") as fh:
    fh.write(f"malicious={malicious_count}\n")
    fh.write(f"scanned={len(to_scan)}\n")
    fh.write(f"unresolved={unresolved_count}\n")

print(
    f"Checked {checked} .bes file(s); {len(all_urls)} distinct download URL(s) found, "
    f"{len(to_scan)} scanned, {malicious_count} flagged malicious, {unresolved_count} unresolved."
)
sys.exit(0)
