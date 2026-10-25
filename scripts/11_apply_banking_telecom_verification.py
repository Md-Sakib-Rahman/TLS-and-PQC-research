#!/usr/bin/env python3
"""
Applies the manual banking/telecom verification verdicts recorded in
data/processed/banking_telecom_review.csv to data/processed/domains_master.csv's
'sector' column.

This is the manual-verification step that flag_finance_telecom.py's own
docstring says no script can do: checking each banking/telecom keyword-match
candidate against bb.org.bd / btrc.gov.bd (or, for a handful of subdomains
under an unconfirmed institution, noting that the specific subdomain itself
was never individually checked even though the parent brand is real). This
script only takes the verdicts once a human has recorded them in the review
CSV's 'verdict' column and turns each one into a clean, categorical sector
label -- it verifies nothing itself.

VERDICT -> SECTOR MAPPING (category is 'banking' or 'telecom', taken from
the row's new_sector so this script never has to guess it):
  Y    -> "{category} (source-verified)"
      Confirmed against the official bank/operator list.
  N    -> "{category} (keyword match -- rejected, false positive)"
      Checked and found NOT to be the institution the keyword suggested.
      Kept as its own labeled tier rather than silently dropped or left
      sitting at "verify manually" forever, so the rejection itself is
      visible in any future sector breakdown.
  FLAG -> "{category} (keyword match -- not yet individually verified)"
      Deliberately NOT called "flagged" or "unresolved" in the sector
      string: for these specific rows nobody has actually tried and failed
      to confirm them (e.g. a subdomain of a real bank's domain that was
      never itself checked) -- calling it a failed check would overstate
      what's known. Kept distinct from both the verified and rejected
      tiers so it doesn't get silently counted as either in downstream
      analysis.

Only the 'sector' column is touched. 'verification_note' and every other
column, and every row not present in the review CSV, are left byte-for-byte
untouched -- row order and content elsewhere in the file do not change.

USAGE:
  python3 apply_banking_telecom_verification.py
"""

import csv
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_PATH = os.path.join(BASE, "data", "processed", "domains_master.csv")
REVIEW_PATH = os.path.join(BASE, "data", "processed", "banking_telecom_review.csv")

VERDICT_SUFFIX = {
    "Y": "(source-verified)",
    "N": "(keyword match -- rejected, false positive)",
    "FLAG": "(keyword match -- not yet individually verified)",
}


def category_from_new_sector(new_sector: str) -> str:
    return new_sector.split(" ", 1)[0]


def load_verdicts(path: str):
    verdicts = {}
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            verdict = row["verdict"].strip().upper()
            if verdict not in VERDICT_SUFFIX:
                raise ValueError(
                    f"Unknown verdict '{row['verdict']}' for domain {row['domain']!r} "
                    f"in {path} -- expected one of {sorted(VERDICT_SUFFIX)}"
                )
            category = category_from_new_sector(row["new_sector"])
            verdicts[row["domain"]] = f"{category} {VERDICT_SUFFIX[verdict]}"
    return verdicts


def main():
    if not os.path.exists(REVIEW_PATH):
        print(f"ERROR: {REVIEW_PATH} not found.")
        return
    if not os.path.exists(MASTER_PATH):
        print(f"ERROR: {MASTER_PATH} not found.")
        return

    verdicts = load_verdicts(REVIEW_PATH)
    print(f"Loaded {len(verdicts)} verdicts from {REVIEW_PATH}")

    with open(MASTER_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)
        rows = list(reader)

    updated = 0
    missing = set(verdicts)
    for row in rows:
        new_sector = verdicts.get(row["domain"])
        if new_sector is None:
            continue
        missing.discard(row["domain"])
        row["sector"] = new_sector
        updated += 1

    if missing:
        print(f"WARNING: {len(missing)} domains from the review CSV were not found in {MASTER_PATH}:")
        for d in sorted(missing):
            print(f"  {d}")

    with open(MASTER_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nUpdated 'sector' for {updated} rows in {MASTER_PATH}")

    from collections import Counter
    breakdown = Counter(v.split(" ", 1)[0] for v in verdicts.values())
    print("\nBy verdict outcome (all rows touched):")
    new_sector_counts = Counter(verdicts.values())
    for sector, n in sorted(new_sector_counts.items()):
        print(f"  {n:3d}  {sector}")


if __name__ == "__main__":
    main()
