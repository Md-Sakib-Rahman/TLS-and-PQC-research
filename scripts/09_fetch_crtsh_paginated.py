#!/usr/bin/env python3
"""
Paginated replacement for fetch_crtsh.sh's broad wildcard queries.

WHY THIS EXISTS: fetch_crtsh.sh's single "%.gov.bd"-style wildcard query
returns a result set that crt.sh silently truncates. Confirmed by checking
not_before dates in every one of the 5 existing raw files under
data/raw/crt_sh/: all five stop around 2015-2018 despite being fetched on
2026-09-13. This isn't a row-count cap (the counts -- 2372, 2476, 3432,
4320, 4760 -- aren't round numbers, and re-querying "%.gov.bd" gave the
identical 977076-byte response both times, so it's deterministic, not
flaky); it lines up with crt.sh's search backend timing out on a very
broad scan and returning whatever it computed within its time budget,
which (given the underlying table's rough insertion-order storage) means
"oldest certificates first, then nothing." A live single-domain check
against khulnadiv.gov.bd confirmed the practical effect: it has 69 real
certificates dated 2023-2026 that the %.gov.bd wildcard pull should have
included and didn't.

TWO PARTITIONING SCHEMES WERE TRIED AND REJECTED before this one -- both
because crt.sh's 'Identity=' field turns out to accept EXACTLY ONE '%'
character, and only in the literal form "%.<suffix>" (percent immediately
followed by a dot). Confirmed empirically: "%k%.gov.bd" (containment) and
"k%.gov.bd" (prefix) both come back "Unsupported use of '%'"; only
"%.<suffix>" is accepted.
  1. Letter-containment ("%<c>%.gov.bd", matching the letter anywhere):
     REJECTED BY CRT.SH -- two wildcards isn't valid syntax at all.
  2. Exact single-character leaf label ("%.a.gov.bd" .. "%.z.gov.bd", the
     originally-suggested form): syntactically valid, but nearly useless --
     it only matches identities whose leaf label immediately before the
     suffix IS the single character "a" (e.g. "a.gov.bd"), missing almost
     every real domain, including khulnadiv.gov.bd itself (leaf label
     "khulnadiv", not "k").

WHAT ACTUALLY WORKS: query "%.<known_domain>" for each REAL domain we
already know about, rather than a guessed letter pattern. Confirmed
empirically: "%.khulnadiv.gov.bd" returns the same 69 up-to-date
certificates as the exact single-domain query. Since gov_hierarchy.csv
(built from the bangladesh-geocode repo) already lists every division and
district's own domain, and virtually every upazila/union subdomain nests
under one of those 64 district + 8 division domains (e.g.
"subilup.comilla.gov.bd" ends in ".comilla.gov.bd"), querying "%.<domain>"
for each of those 72 known suffixes is: (a) syntactically valid, (b) far
narrower per-query than "%.gov.bd" so it should finish inside crt.sh's
time budget, and (c) union/upazila-aware, unlike a blind letter scheme.

The same technique generalizes to any suffix with its own known-domain
source list: ac.bd/edu.bd use universities_ugc.csv (filtered to rows whose
base_domain actually ends in that suffix -- the file also has a handful of
non-.bd domains like "aust.edu", which aren't usable as a ".ac.bd"/
".edu.bd" suffix query and are skipped).

LIMITATION: com.bd and all_bd have no comparable known-domain source list
in this project, and building one is out of scope right now. Their
existing raw pulls (com_bd_*.json, all_bd_*.json) remain affected by the
original truncation issue -- documented here, not fixed.

Also, for gov.bd specifically: agencies/ministries not nested under a
division or district name (e.g. "achallan.gov.bd", "aap.gov.bd") won't be
caught by the 72 targeted queries either. The existing broad gov_bd_*.json
pull is merged in alongside the targeted results specifically to still
cover those, even though that file is itself stale past ~2018 for domains
not covered by a targeted query.

Output: one raw JSON file per targeted suffix+domain in
data/raw/crt_sh/paginated/ (filenames prefixed with the suffix tag so
fetching multiple suffixes on the same day can't merge each other's
bucket files together), plus one merged+deduped file per suffix:
  data/raw/crt_sh/<suffix_tag>_paginated_<date>.json

USAGE:
  python3 fetch_crtsh_paginated.py gov.bd
  python3 fetch_crtsh_paginated.py ac.bd edu.bd
"""

import csv
import glob
import json
import os
import subprocess
import sys
import time
from datetime import date

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def looks_like_json_array(path: str) -> bool:
    """First-byte '[' alone isn't enough: crt.sh's "Unsupported use of '%'"
    error page is wrapped as "[BEGIN_HEADERS]...[END_HEADERS]<html>...",
    which also starts with '['. Checking the last non-whitespace byte is
    ']' too is cheap and rules that shape out without a full JSON parse."""
    with open(path, "rb") as f:
        data = f.read()
    stripped = data.strip()
    return stripped[:1] == b"[" and stripped[-1:] == b"]"


BUCKET_DIR = os.path.join(BASE, "data", "raw", "crt_sh", "paginated")
CRT_SH_DIR = os.path.join(BASE, "data", "raw", "crt_sh")
SOURCE_LISTS_DIR = os.path.join(BASE, "data", "raw", "sector_authority_lists")
HIERARCHY_PATH = os.path.join(SOURCE_LISTS_DIR, "gov_hierarchy.csv")
UNIVERSITIES_PATH = os.path.join(SOURCE_LISTS_DIR, "universities_ugc.csv")
DATE_TAG = date.today().isoformat()


def known_suffixes_for(suffix: str):
    """Known real domains ending in `suffix`, drawn from whichever source
    list applies. Falls back to just the bare suffix itself (i.e. no
    narrowing -- same as the original broad pull) if no source list
    applies, which is the documented, deliberate case for com.bd/all_bd."""
    if suffix == "gov.bd" and os.path.exists(HIERARCHY_PATH):
        domains = []
        with open(HIERARCHY_PATH, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["tier"] in ("division", "district") and row["base_domain"]:
                    domains.append(row["base_domain"])
        return sorted(set(domains))

    if suffix in ("ac.bd", "edu.bd") and os.path.exists(UNIVERSITIES_PATH):
        domains = []
        with open(UNIVERSITIES_PATH, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                bd = row["base_domain"].strip().lower()
                if bd.endswith(f".{suffix}"):
                    domains.append(bd)
        return sorted(set(domains))

    return [suffix]


def fetch_one(suffix: str, known_domain: str, max_retries=2):
    # '%' must be percent-encoded as %25 -- crt.sh's 'Identity=' field only
    # accepts a literal %25 immediately followed by a dot as its wildcard;
    # see module docstring for the two forms that were tried and rejected.
    url_pattern = f"%25.{known_domain}"
    tag = suffix.replace(".", "_")
    safe_name = known_domain.replace(".", "_")
    # Prefixed with the suffix tag so fetching multiple suffixes on the same
    # day (e.g. ac.bd and edu.bd back to back) can't have merge_all() for one
    # suffix accidentally scoop up another suffix's bucket files via a bare
    # date-glob -- exactly the bug that would have hit gov.bd + ac.bd/edu.bd.
    outpath = os.path.join(BUCKET_DIR, f"{tag}__{safe_name}_{DATE_TAG}.json")

    # Resume support: if a previous run already saved a valid (non-empty,
    # starts-with-'[') result for this exact domain+date, don't re-fetch it.
    # This matters because a crash partway through (e.g. merge_all() hitting
    # one bad file) shouldn't force re-paying for every already-successful
    # query -- each one costs real wall-clock time against a rate-limited
    # public service.
    if os.path.exists(outpath) and os.path.getsize(outpath) > 0 and looks_like_json_array(outpath):
        return outpath

    for attempt in range(max_retries + 1):
        result = subprocess.run(
            [
                "curl", "-sS", "--max-time", "90", "--retry", "2", "--retry-delay", "5",
                "-w", "%{http_code}",
                "-o", outpath,
                f"https://crt.sh/?Identity={url_pattern}&output=json",
            ],
            capture_output=True, text=True,
        )
        http_code = result.stdout.strip()

        ok = (
            result.returncode == 0
            and http_code == "200"
            and os.path.exists(outpath)
            and os.path.getsize(outpath) > 0
        )
        if ok:
            ok = looks_like_json_array(outpath)
        if ok:
            return outpath

        if attempt < max_retries:
            time.sleep(5)
            continue
        # Give up: remove whatever curl left at outpath (empty file, error
        # page, or partial download from the last attempt) so merge_all()'s
        # glob doesn't pick up a non-JSON file and crash on it.
        if os.path.exists(outpath):
            os.remove(outpath)
        return None


def merge_all(suffix: str):
    tag = suffix.replace(".", "_")
    bucket_files = sorted(glob.glob(os.path.join(BUCKET_DIR, f"{tag}__*_{DATE_TAG}.json")))
    existing_broad = os.path.join(CRT_SH_DIR, f"{tag}_2026-09-13.json")

    by_id = {}
    skipped = []
    for path in bucket_files:
        try:
            with open(path, encoding="utf-8") as f:
                records = json.load(f)
        except json.JSONDecodeError:
            # Defensive: a single unreadable bucket file (leftover from a
            # crashed run, manually inspected, etc.) shouldn't discard every
            # other successfully-fetched bucket's data.
            skipped.append(path)
            continue
        for r in records:
            by_id[r["id"]] = r
    if skipped:
        print(f"  WARNING: skipped {len(skipped)} unreadable bucket file(s): {skipped}")
    if os.path.exists(existing_broad):
        with open(existing_broad, encoding="utf-8") as f:
            for r in json.load(f):
                by_id[r["id"]] = r

    merged_path = os.path.join(CRT_SH_DIR, f"{tag}_paginated_{DATE_TAG}.json")
    with open(merged_path, "w", encoding="utf-8") as f:
        json.dump(list(by_id.values()), f)
    return merged_path, list(by_id.values())


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 fetch_crtsh_paginated.py <suffix> [<suffix> ...]")
        sys.exit(1)

    os.makedirs(BUCKET_DIR, exist_ok=True)

    for suffix in sys.argv[1:]:
        domains = known_suffixes_for(suffix)
        print(f"=== {suffix}: {len(domains)} targeted sub-queries (known real domains from source list) ===")
        failed = []
        for domain in domains:
            outpath = fetch_one(suffix, domain)
            if outpath is None:
                failed.append(domain)
                print(f"  %.{domain}: FAILED")
            else:
                count = len(json.load(open(outpath, encoding="utf-8")))
                print(f"  %.{domain}: {count} records")
            time.sleep(3)  # polite delay, same as fetch_crtsh.sh

        merged_path, merged_records = merge_all(suffix)
        print(f"  Merged & deduped by cert id (targeted queries + existing broad pull): "
              f"{len(merged_records)} unique certificates -> {merged_path}")
        if failed:
            print(f"  WARNING: {len(failed)}/{len(domains)} sub-queries failed: {failed}")
        print()


if __name__ == "__main__":
    main()
