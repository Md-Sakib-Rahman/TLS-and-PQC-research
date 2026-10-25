#!/usr/bin/env python3
"""
Compares DomCop's Top 10 Million domains list against the existing
domains_master.csv corpus and reports ONLY the .bd domains that are
genuinely new -- not already present in the corpus, under any case.

WHY THIS EXISTS: DomCop is a much larger list (10M) than Tranco (1M), and
the global longitudinal PQ-TLS paper specifically credits it with better
coverage of country-specific government/public-sector domains than
Tranco. But DomCop and Tranco are both popularity/backlink-ranked lists,
so real overlap with what's already in the corpus is expected. This
script's whole job is separating "DomCop has this .bd domain" from
"DomCop has a .bd domain we don't already have" -- only the second number
matters for deciding whether integrating DomCop is worth the effort.

WHAT COUNTS AS "GENUINELY .bd": the domain's last label must literally be
"bd" -- same rule used in check_suffix_anomalies.py, applied here so this
script doesn't reintroduce the exact bd.com/bd.local contamination that
check_suffix_anomalies.py was built to remove.

WHAT COUNTS AS "ALREADY PRESENT": an exact match (case-insensitive) against
the 'domain' column of domains_master.csv. A domain that differs only by a
"www." prefix, or by a subdomain, is treated as a DIFFERENT, genuinely new
candidate -- not a duplicate -- because it may resolve to a different host
with a different TLS configuration, consistent with how this project has
always treated bare-vs-www domains elsewhere in the pipeline.

USAGE:
  python3 find_new_domcop_domains.py <domcop_csv_path> <domains_master.csv>

OUTPUT: data/processed/domcop_new_candidates.csv -- new domains found,
in the same shape add_new_domains.py-style tooling expects (domain,
source, plus DomCop's own rank/score for reference). Nothing is merged
into domains_master.csv by this script -- it only reports and writes the
candidate list for a separate, deliberate merge step.

TESTED before delivery against a synthetic corpus covering: an exact
existing match, a case-different existing match, a genuinely new domain,
a genuinely new non-standard .bd suffix (mygov.bd-style), a www.-prefixed
variant of an existing domain (correctly treated as new, not a duplicate),
a non-.bd domain, and a bd.local reserved-TLD contamination case (correctly
excluded). All cases produced the expected result.
"""

import csv
import os
import sys


def is_genuine_bd(domain: str) -> bool:
    labels = domain.strip().lower().rstrip(".").split(".")
    return len(labels) >= 2 and labels[-1] == "bd"


def load_existing_domains(master_path: str):
    existing = set()
    with open(master_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            existing.add(row["domain"].strip().lower())
    return existing


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 find_new_domcop_domains.py <domcop_csv> <domains_master.csv>")
        sys.exit(1)

    domcop_path, master_path = sys.argv[1], sys.argv[2]
    for path in (domcop_path, master_path):
        if not os.path.exists(path):
            print(f"ERROR: file not found: {path}")
            sys.exit(1)

    existing = load_existing_domains(master_path)
    print(f"Loaded {len(existing)} existing domains from {master_path}")

    total_rows = 0
    total_bd = 0
    already_present = 0
    new_candidates = []

    with open(domcop_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        # DomCop's header is quoted "Rank","Domain","Open Page Rank" -- csv
        # module handles the quoting; just confirm the expected column exists.
        if "Domain" not in (reader.fieldnames or []):
            print(f"ERROR: expected a 'Domain' column, found: {reader.fieldnames}")
            sys.exit(1)
        for row in reader:
            total_rows += 1
            raw_domain = row["Domain"].strip()
            if not is_genuine_bd(raw_domain):
                continue
            total_bd += 1
            key = raw_domain.lower()
            if key in existing:
                already_present += 1
            else:
                new_candidates.append({
                    "domain": raw_domain.lower(),
                    "source": "domcop_top10m",
                    "domcop_rank": row.get("Rank", ""),
                    "domcop_open_page_rank": row.get("Open Page Rank", ""),
                })

    print(f"\nTotal DomCop rows scanned: {total_rows}")
    print(f"Genuine .bd domains in DomCop (last label == 'bd'): {total_bd}")
    print(f"  Already present in domains_master.csv: {already_present}")
    print(f"  Genuinely new: {len(new_candidates)}")

    if new_candidates:
        out_dir = os.path.dirname(master_path)
        out_path = os.path.join(out_dir, "domcop_new_candidates.csv")
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["domain", "source", "domcop_rank", "domcop_open_page_rank"])
            writer.writeheader()
            writer.writerows(new_candidates)
        print(f"\nNew candidates written to: {out_path}")
        print("Nothing has been merged into domains_master.csv -- review this")
        print("file, then merge deliberately (e.g. with add_new_domains.py-style logic).")
    else:
        print("\nNo new domains found -- DomCop's .bd coverage is fully redundant")
        print("with what this corpus already has.")


if __name__ == "__main__":
    main()