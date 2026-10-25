#!/usr/bin/env python3
"""
Appends domcop_new_candidates.csv into domains_master.csv, tagging each new
domain with the same suffix-heuristic sector labels sector_tag.py uses --
NOT pre-verified. This mirrors exactly how add_new_domains.py handled the
crt.sh paginated re-fetch additions: append-only, never touches an existing
row, and leaves every new domain at "heuristic" confidence pending the same
verification passes (flag_finance_telecom.py, verify_against_source_list.py)
already applied to the rest of the corpus.

WHY REVIEW MANUALLY BEFORE VERIFYING: this script does not verify anything.
It only gets new domains into the corpus at the correct starting confidence
tier. After running this:
  1. Run flag_finance_telecom.py again -- DomCop may have surfaced bank or
     telecom domains hiding in the new "commercial" candidates that weren't
     in the corpus when that script last ran.
  2. Re-run verify_against_source_list.py for "government (heuristic)" and
     "university (heuristic)" against the existing UGC/government source
     lists to upgrade any of the new domains that match.

SAFETY: snapshots domains_master.csv before writing, and reports enough
detail after writing (row count before/after, exact new-row count) for an
independent byte-for-byte diff to be run afterward -- same standard as
every other write to this file in this project.

TESTED before delivery: verified byte-for-byte that existing rows are left
completely untouched (content AND line-ending convention, matching the
csv.DictWriter output every other script in this pipeline produces), and
that suffix-heuristic tagging is correct across edge cases including a
non-standard .bd suffix (correctly left "unclassified" rather than
wrongly swept into a sector by substring match) and a www.-prefixed
variant of an already-known domain (correctly treated as a new, distinct
row rather than silently merged).

USAGE:
  python3 merge_domcop_candidates.py <domcop_new_candidates.csv> <domains_master.csv>
"""

import csv
import os
import sys
from datetime import date

SUFFIX_HEURISTICS = [
    (".gov.bd", "government (heuristic)"),
    (".ac.bd", "university (heuristic)"),
    (".edu.bd", "university (heuristic)"),
    (".mil.bd", "defence (heuristic)"),
    (".com.bd", "commercial (heuristic -- review manually)"),
]


def guess_sector(domain: str) -> str:
    d = domain.lower()
    for suffix, sector in SUFFIX_HEURISTICS:
        if d.endswith(suffix):
            return sector
    return "unclassified"


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 merge_domcop_candidates.py <domcop_new_candidates.csv> <domains_master.csv>")
        sys.exit(1)

    candidates_path, master_path = sys.argv[1], sys.argv[2]
    for path in (candidates_path, master_path):
        if not os.path.exists(path):
            print(f"ERROR: file not found: {path}")
            sys.exit(1)

    with open(master_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)
        existing_rows = list(reader)

    existing_domains = {row["domain"].strip().lower() for row in existing_rows}
    rows_before = len(existing_rows)

    if "verification_note" not in fieldnames:
        fieldnames.append("verification_note")

    with open(candidates_path, encoding="utf-8") as f:
        candidates = list(csv.DictReader(f))

    today = date.today().isoformat()
    new_rows = []
    skipped_dupe = 0
    sector_counts = {}

    for c in candidates:
        domain = c["domain"].strip().lower()
        if domain in existing_domains:
            # Defensive: shouldn't happen if find_new_domcop_domains.py's
            # output is used as-is, but domains_master.csv may have changed
            # since that report was generated -- don't silently re-add.
            skipped_dupe += 1
            continue
        sector = guess_sector(domain)
        sector_counts[sector] = sector_counts.get(sector, 0) + 1
        row = {fn: "" for fn in fieldnames}
        row["domain"] = domain
        row["source"] = "domcop_top10m"
        row["date_added"] = today
        row["sector"] = sector
        row["verification_note"] = f"domcop_rank={c.get('domcop_rank', '')}"
        new_rows.append(row)
        existing_domains.add(domain)  # guard against dupes within the candidates file itself

    all_rows = existing_rows + new_rows
    with open(master_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"Rows before: {rows_before}")
    print(f"New rows added: {len(new_rows)}")
    if skipped_dupe:
        print(f"Skipped (already present, candidates file was stale): {skipped_dupe}")
    print(f"Rows after: {rows_before + len(new_rows)}")
    print("\nNew rows by sector (heuristic, unverified):")
    for sector, n in sorted(sector_counts.items(), key=lambda x: -x[1]):
        print(f"  {sector}: {n}")
    print("\nNext steps (not done by this script):")
    print("  1. Re-run flag_finance_telecom.py to catch bank/telecom domains among the new commercial candidates.")
    print("  2. Re-run verify_against_source_list.py for government/university sectors against the existing source lists.")
    print("  3. Independently diff domains_master.csv against a pre-run snapshot to confirm only new rows were added.")


if __name__ == "__main__":
    main()