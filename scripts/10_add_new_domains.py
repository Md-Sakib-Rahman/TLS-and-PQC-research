#!/usr/bin/env python3
"""
Appends genuinely-new domains found by the paginated crt.sh re-fetch
(gov_bd_paginated_*.json, ac_bd_paginated_*.json, edu_bd_paginated_*.json)
to data/processed/domains_master.csv, WITHOUT rewriting the file from
scratch the way merge_and_dedupe.py does.

WHY THIS SCRIPT EXISTS, NOT JUST RE-RUNNING merge_and_dedupe.py: that
script's output columns are only domain,source,date_added -- it has no
concept of 'sector' or 'verification_note' at all (those are added by
sector_tag.py / verify_against_source_list.py / flag_finance_telecom.py in
later, separate passes). Re-running it would produce a fresh 3-column file
that clobbers the 4 sectors' worth of verification work already done
(university, government, banking, telecom institution-verified/not-verified
states, and every verification_note explaining why). This script instead
APPENDS new 5-column rows in the file's actual current schema and leaves
every existing row byte-for-byte untouched -- it opens the file in append
mode and never reads existing rows back out to rewrite them.

Parsing logic for extracting domain names from a crt.sh JSON file is
copied from merge_and_dedupe.py's load_crtsh() (clean() + is_plausible_domain())
rather than reimplemented, imported directly so the two scripts can't drift
out of sync on what counts as a "plausible domain."

Sector assignment for new rows uses sector_tag.py's own logic directly
(load_authority_map() + guess_sector(), same precedence sector_tag.py
itself uses) rather than reimplementing the suffix heuristic table here.

Output: appends new rows to data/processed/domains_master.csv with
  source            = basename of the paginated file the domain first
                       appeared in (e.g. "gov_bd_paginated_2026-09-14.json")
  date_added        = today
  sector            = sector_tag.py's authority-map-or-suffix-heuristic
                       result (a fresh "X (heuristic)" tag, same as any
                       domain would get on its first pass through
                       sector_tag.py)
  verification_note = "" (empty -- these haven't been verified yet)

USAGE:
  python3 add_new_domains.py
"""

import csv
import os
import sys
from collections import Counter
from datetime import date

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRT_SH_DIR = os.path.join(BASE, "data", "raw", "crt_sh")
MASTER_PATH = os.path.join(BASE, "data", "processed", "domains_master.csv")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from merge_and_dedupe import clean, is_plausible_domain  # noqa: E402
from sector_tag import load_authority_map, guess_sector  # noqa: E402

TARGET_FILES = [
    "gov_bd_paginated_2026-09-14.json",
    "ac_bd_paginated_2026-09-14.json",
    "edu_bd_paginated_2026-09-14.json",
]

FIELDNAMES = ["domain", "source", "date_added", "sector", "verification_note"]


def load_new_pull_domains():
    """Same per-record name_value parsing as merge_and_dedupe.py's
    load_crtsh(), scoped to just the 3 paginated files (not every file
    under data/raw/crt_sh/, which would re-see domains already merged in
    from the original, pre-paginated pulls)."""
    import json

    found = {}
    for filename in TARGET_FILES:
        path = os.path.join(CRT_SH_DIR, filename)
        if not os.path.exists(path):
            print(f"  WARNING: {path} not found, skipping")
            continue
        with open(path, encoding="utf-8") as f:
            records = json.load(f)
        for rec in records:
            raw_names = rec.get("name_value", "")
            for n in raw_names.split("\n"):
                n = clean(n)
                if is_plausible_domain(n):
                    found.setdefault(n, filename)
    return found


def main():
    if not os.path.exists(MASTER_PATH):
        print(f"ERROR: {MASTER_PATH} not found.")
        sys.exit(1)

    with open(MASTER_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != FIELDNAMES:
            print(f"ERROR: {MASTER_PATH} columns are {reader.fieldnames}, expected {FIELDNAMES}. Aborting rather than appending mismatched rows.")
            sys.exit(1)
        existing_domains = {row["domain"] for row in reader}

    print(f"Existing rows in {os.path.basename(MASTER_PATH)}: {len(existing_domains)}")

    pulled = load_new_pull_domains()
    print(f"Domains found across the 3 paginated files: {len(pulled)}")

    authority_map = load_authority_map()

    new_rows = []
    today = date.today().isoformat()
    for domain, source in sorted(pulled.items()):
        if domain in existing_domains:
            continue
        sector = authority_map.get(domain) or guess_sector(domain)
        new_rows.append({
            "domain": domain,
            "source": source,
            "date_added": today,
            "sector": sector,
            "verification_note": "",
        })

    if not new_rows:
        print("\nNo genuinely new domains found. Nothing appended.")
        return

    # Append-only: existing rows are never read back out or rewritten.
    with open(MASTER_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writerows(new_rows)

    print(f"\nAppended {len(new_rows)} genuinely new domains to {MASTER_PATH}")
    print("\nNew domains by sector:")
    for sector, n in Counter(r["sector"] for r in new_rows).most_common():
        print(f"  {sector}: {n}")


if __name__ == "__main__":
    main()
