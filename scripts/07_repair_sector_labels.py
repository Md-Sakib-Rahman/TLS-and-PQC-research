#!/usr/bin/env python3
"""
ONE-TIME REPAIR for data/processed/domains_master.csv.

An earlier version of verify_against_source_list.py embedded the specific
unmatched base domain directly into the 'sector' column for every non-match,
e.g.:
    university (heuristic -- base domain 'tecn.ac.bd' not found in source list)
    university (heuristic -- base domain 'mist.ac.bd' not found in source list)
    ... (one near-unique string per distinct unmatched domain)

This turns 'sector' -- which every other tool in this project (the Coverage
Tracker, `cut -f4 | sort | uniq -c` reports, the paper's sector-wise table)
treats as a small categorical field -- into 1700+ nearly-unique values.
Confirmed by a sector breakdown that printed 339+ lines instead of ~15.

This script finds any sector value matching that polluted pattern, restores
a clean categorical sector label, and moves the specific domain detail into
a separate 'verification_note' column instead (added if not already present)
-- so no information is lost, it's just in the right column now.

Safe to run multiple times (idempotent): rows that are already clean are
left untouched.
"""

import csv
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_PATH = os.path.join(BASE, "data", "processed", "domains_master.csv")

NOT_FOUND_PATTERN = re.compile(
    r"^(?P<category>[a-zA-Z]+) \(heuristic -- base domain '(?P<base>[^']*)' not found in source list\)$"
)
EXTRACTION_PATTERN = re.compile(
    r"^(?P<category>[a-zA-Z]+ \([a-zA-Z]+\)) -- EXTRACTION ISSUE: (?P<note>.+)$"
)


def main():
    if not os.path.exists(MASTER_PATH):
        print(f"ERROR: {MASTER_PATH} not found.")
        return

    with open(MASTER_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)
        rows = list(reader)

    if "verification_note" not in fieldnames:
        fieldnames.append("verification_note")

    repaired_not_found = 0
    repaired_extraction = 0

    for row in rows:
        sector = row.get("sector", "")

        m = NOT_FOUND_PATTERN.match(sector)
        if m:
            category = m.group("category")
            base = m.group("base")
            row["sector"] = f"{category} (heuristic -- not verified)"
            row["verification_note"] = f"base domain '{base}' not found in source list"
            repaired_not_found += 1
            continue

        m = EXTRACTION_PATTERN.match(sector)
        if m:
            category_full = m.group("category")  # e.g. "university (heuristic)"
            category = category_full.split(" (")[0]
            note = m.group("note")
            row["sector"] = f"{category} (heuristic -- extraction issue)"
            row["verification_note"] = note
            repaired_extraction += 1
            continue

        # already clean (institution-verified, or never touched by the buggy
        # script) -- ensure the column exists for consistency, leave value as-is
        row.setdefault("verification_note", "")

    with open(MASTER_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Repaired {repaired_not_found} polluted 'not found' sector values.")
    print(f"Repaired {repaired_extraction} polluted 'extraction issue' sector values.")
    print(f"Total rows: {len(rows)}")

    from collections import Counter
    breakdown = Counter(r["sector"] for r in rows)
    print(f"\nClean sector breakdown now has {len(breakdown)} distinct categories (should be ~10-15, not 300+):")
    for sector, n in breakdown.most_common():
        print(f"  {n:6d}  {sector}")


if __name__ == "__main__":
    main()
