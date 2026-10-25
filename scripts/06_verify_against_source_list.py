#!/usr/bin/env python3
"""
Upgrades a sector from "heuristic" (suffix-only guess) to "institution-verified"
by checking each domain's BASE (registrable) domain against an official source
list -- not by checking every subdomain individually.

WHY BASE-DOMAIN, NOT ONLY FULL-DOMAIN MATCHING:
Bangladesh's .ac.bd/.gov.bd/.com.bd act as pseudo-TLDs (like .co.uk). A real
institution's domain is the label immediately before that suffix -- e.g. for
"mail.iiuc.ac.bd", the institution is "iiuc.ac.bd", and "mail." is just a
subdomain of it. Checking "mail.iiuc.ac.bd" against a source list that only
contains "iiuc.ac.bd" would incorrectly fail as a non-match. For source
lists built at the institution-root level (universities_ugc.csv,
gov_national_portal.csv), this script strips subdomains down to that level
before comparing, then applies that institution's verification status to
every subdomain beneath it.

MATCHING ORDER: exact full-domain match first, then 3-label-base fallback.
Not every source list is institution-root-only, though. gov_hierarchy.csv
lists Bangladesh's union/upazila government sites at their FULL, variable
depth (e.g. "subilup.comilla.gov.bd") because for those, unlike a university
mail server, the extra label IS the institution identity, not a subdomain of
one -- reducing it to 3 labels would wrongly collapse thousands of distinct
union/upazila entities down to their shared district domain. So each
candidate domain is checked two ways: first for an exact match against the
source list as given (catches variable-depth entries like a union site
listed at 4 labels), then -- only if that fails -- reduced to its 3-label
base and checked again (catches institution-root source lists, and
deeper subdomains of a variable-depth entry). This order never changes the
outcome for a source list that is already all 3-label entries: an exact
match there implies the 3-label match would have succeeded anyway.

THIS IS STILL A HEURISTIC AT THE EXTRACTION STEP: the base-domain fallback
assumes a standard 3-label pattern (name.suffix1.suffix2, e.g. iiuc.ac.bd).
A minority of real domains may not fit this (e.g. a domain registered
directly as "somename.bd" with no middle suffix). Domains that don't fit
the expected pattern are flagged, not silently mismatched -- check the
'extraction_note' column in the output.

USAGE:
  python3 verify_against_source_list.py <sector_tag> <source_list.csv>

  <sector_tag>       exact sector string to process, e.g.:
                       "university (heuristic)"
                       "government (heuristic)"
  <source_list.csv>  CSV with one column named 'base_domain', containing the
                       official base domains for that sector (one per
                       institution/ministry). You build this file by hand
                       or by having Claude Code fetch and extract it from
                       UGC's site (university) or the National Web Portal
                       (government) -- see README for why this project
                       can't fetch those sites directly from this chat.

OUTPUT: updates data/processed/domains_master.csv in place, changing the
sector for matched rows from "X (heuristic)" to "X (institution-verified)",
and leaving non-matches as "X (heuristic -- not found in source list)" so
you can see exactly what didn't verify, rather than losing that information.
"""

import csv
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_PATH = os.path.join(BASE, "data", "processed", "domains_master.csv")


def extract_base_domain(domain: str):
    """
    Returns (base_domain, note). note is None if extraction was straightforward,
    otherwise explains why this domain needed special handling.
    """
    labels = domain.strip(".").split(".")
    if len(labels) < 3:
        # e.g. bare "gov.bd" with no institution label at all -- unusual,
        # can't extract an institution name, flag it rather than guess.
        return domain, "fewer than 3 labels -- could not extract an institution-level base domain"
    base = ".".join(labels[-3:])
    if len(labels) > 3:
        return base, None  # normal case: subdomain(s) stripped down to institution.suffix.bd
    return base, None  # exactly 3 labels: domain already IS the base


def load_source_list(path: str):
    bases = set()
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if "base_domain" not in (reader.fieldnames or []):
            print(f"ERROR: {path} must have a 'base_domain' column. Found: {reader.fieldnames}")
            sys.exit(1)
        for row in reader:
            bd = row["base_domain"].strip().lower()
            if bd:
                bases.add(bd)
    return bases


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 verify_against_source_list.py <sector_tag> <source_list.csv>")
        print('Example: python3 verify_against_source_list.py "university (heuristic)" ../data/raw/sector_authority_lists/universities_ugc.csv')
        sys.exit(1)

    sector_tag = sys.argv[1]
    source_path = sys.argv[2]

    if not os.path.exists(source_path):
        print(f"ERROR: source list not found: {source_path}")
        sys.exit(1)
    if not os.path.exists(MASTER_PATH):
        print(f"ERROR: {MASTER_PATH} not found.")
        sys.exit(1)

    official_bases = load_source_list(source_path)
    print(f"Loaded {len(official_bases)} official base domains from {source_path}")

    with open(MASTER_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)
        rows = list(reader)

    # IMPORTANT: 'sector' must stay a small, categorical field -- it's the
    # column everything else (the Coverage Tracker, `cut | uniq -c` reports,
    # the paper's sector-wise table) groups by. Any per-domain detail (which
    # base domain, why it didn't match) goes in a SEPARATE 'verification_note'
    # column instead. An earlier version of this script embedded the specific
    # unmatched base domain directly into the sector string, which silently
    # exploded the sector column into 1000+ near-unique values -- caught via
    # a sector breakdown that printed "+339 lines" instead of a normal ~15.
    # If you're fixing already-polluted data from that version, use
    # repair_sector_labels.py first, not this script.
    if "verification_note" not in fieldnames:
        fieldnames.append("verification_note")

    verified = 0
    not_found = 0
    extraction_issues = 0
    unmatched_bases = set()

    for row in rows:
        if row.get("sector") != sector_tag:
            continue
        category = sector_tag.split(" (")[0]
        full_domain = row["domain"].strip().lower()

        if full_domain in official_bases:
            row["sector"] = f"{category} (institution-verified)"
            row["verification_note"] = f"exact domain match: {full_domain}"
            verified += 1
            continue

        base, note = extract_base_domain(row["domain"])
        if note:
            extraction_issues += 1
            row["sector"] = f"{category} (heuristic -- extraction issue)"
            row["verification_note"] = note
            continue
        if base.lower() in official_bases:
            row["sector"] = f"{category} (institution-verified)"
            row["verification_note"] = f"base domain: {base}"
            verified += 1
        else:
            row["sector"] = f"{category} (heuristic -- not verified)"
            row["verification_note"] = f"base domain '{base}' not found in source list"
            not_found += 1
            unmatched_bases.add(base)

    with open(MASTER_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nVerified (institution found in source list): {verified}")
    print(f"Not found in source list: {not_found}")
    print(f"Extraction issues (couldn't determine base domain): {extraction_issues}")

    if unmatched_bases:
        print(f"\n{len(unmatched_bases)} distinct base domains were NOT in the source list:")
        for b in sorted(unmatched_bases)[:20]:
            print(f"  {b}")
        if len(unmatched_bases) > 20:
            print(f"  ... and {len(unmatched_bases) - 20} more")
        print("\nThese aren't necessarily wrong -- the source list itself might be incomplete")
        print("(e.g. UGC/portal pages miss an institution, or use a different domain than")
        print("the one actually in use). Spot-check a few before assuming they're invalid.")


if __name__ == "__main__":
    main()
