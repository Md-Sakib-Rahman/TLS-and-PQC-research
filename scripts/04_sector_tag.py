#!/usr/bin/env python3
"""
Adds a 'sector' column to data/processed/domains_master.csv.

Tagging logic, in priority order:
  1. Exact match against a manually compiled sector authority list
     (data/raw/sector_authority_lists/*.csv, columns: domain,sector,source_name)
     -- this is the ONLY reliable source of ground truth (e.g. a bank's real
     domain vs. a lookalike/phishing domain that also happens to be under .bd).
  2. Suffix heuristics, clearly marked as heuristic-only in the output --
     these are a starting point for manual review, not a substitute for it.

Known suffix conventions in Bangladesh (heuristic, not authoritative):
  .gov.bd            -> government
  .ac.bd / .edu.bd   -> university / education
  .com.bd            -> commercial (could be e-commerce, corporate, anything)
  .mil.bd            -> military/defence
  .net.bd / .org.bd  -> ambiguous, needs manual review

A domain that matches NO authority list and NO suffix heuristic is tagged
'unclassified' -- do not silently drop these, they need a human look before
the next phase.
"""

import csv
import glob
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_PATH = os.path.join(BASE, "data", "processed", "domains_master.csv")
RAW_AUTHORITY = os.path.join(BASE, "data", "raw", "sector_authority_lists")

SUFFIX_HEURISTICS = [
    (".gov.bd", "government (heuristic)"),
    (".ac.bd", "university (heuristic)"),
    (".edu.bd", "university (heuristic)"),
    (".mil.bd", "defence (heuristic)"),
    (".com.bd", "commercial (heuristic -- review manually)"),
]


def load_authority_map():
    mapping = {}
    for path in glob.glob(os.path.join(RAW_AUTHORITY, "*.csv")):
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get("domain", "").strip().lower()
                sector = row.get("sector", "").strip()
                if domain and sector:
                    mapping[domain] = sector
    return mapping


def guess_sector(domain: str) -> str:
    for suffix, sector in SUFFIX_HEURISTICS:
        if domain.endswith(suffix):
            return sector
    return "unclassified"


def main():
    if not os.path.exists(MASTER_PATH):
        print(f"ERROR: {MASTER_PATH} not found. Run merge_and_dedupe.py first.")
        return

    authority_map = load_authority_map()
    print(f"Loaded {len(authority_map)} authoritative domain->sector mappings.")

    rows = []
    with open(MASTER_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames + ["sector"] if "sector" not in reader.fieldnames else reader.fieldnames
        for row in reader:
            domain = row["domain"]
            row["sector"] = authority_map.get(domain) or guess_sector(domain)
            rows.append(row)

    with open(MASTER_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    from collections import Counter
    counts = Counter(r["sector"] for r in rows)
    print("\nSector breakdown:")
    for sector, n in counts.most_common():
        print(f"  {sector}: {n}")

    unclassified = counts.get("unclassified", 0)
    if unclassified:
        print(f"\n{unclassified} domains are unclassified -- review these manually before scanning.")


if __name__ == "__main__":
    main()
