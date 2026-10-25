#!/usr/bin/env python3
"""
Checks that every domain in domains_master.csv genuinely belongs to Bangladesh's
.bd ccTLD -- i.e. that the LAST label of the domain is literally "bd" -- and
flags anything that doesn't, rather than assuming a domain is legitimate just
because "bd" appears somewhere in the string.

WHY THIS CHECK EXISTS: the EDA notebook's top-suffix chart surfaced entries
like ".bd.com", ".mygov.bd", and ".bd.local" in the top 10. These look similar
at a glance but are NOT equivalent:
  - "portal.bd.com" ends in ".com" -- this is a .com domain that happens to
    start with "bd", NOT a Bangladesh ccTLD domain at all. Genuine corpus
    contamination if found.
  - "mygov.bd" ends in ".bd" -- structurally a real, valid .bd domain, just
    using a second-level label ("mygov") that isn't one of the standard
    government/education/commercial conventions this project's suffix
    heuristics were built around. Possibly legitimate (analogous to India's
    "mygov.in"), worth a manual look rather than assuming it's wrong.
  - "test.bd.local" ends in ".local" -- .local is a reserved special-use TLD
    (RFC 6762, mDNS/Bonjour local network resolution), never a real public
    Internet domain. Almost certainly contamination -- likely an internal
    hostname that leaked into a public Certificate Transparency log.

This script separates these into distinct categories instead of treating
"contains bd" as good enough, and never silently drops anything -- every
flagged domain is written to a review CSV, not deleted.

Output: data/processed/suffix_anomaly_review.csv
"""

import csv
import os
import sys
from collections import Counter

MASTER_PATH = sys.argv[1] if len(sys.argv) > 1 else "../data/processed/domains_master.csv"
OUT_PATH = os.path.join(os.path.dirname(MASTER_PATH), "suffix_anomaly_review.csv")


def classify(domain: str):
    labels = domain.strip().lower().rstrip(".").split(".")
    if not labels:
        return "malformed", "empty domain string"
    last_label = labels[-1]
    if last_label != "bd":
        return "NOT .bd ccTLD", f"last label is '.{last_label}', not '.bd' -- likely contamination"
    if len(labels) < 2:
        return "malformed", "bare 'bd' with no second-level label at all"
    second_last = labels[-2]
    standard_suffixes = {"gov", "ac", "edu", "com", "mil", "net", "org", "info"}
    if second_last in standard_suffixes:
        return "standard .bd suffix", f"recognized second-level label: .{second_last}.bd"
    if second_last == "local":
        return "reserved TLD leak", "second-level label is 'local' -- RFC 6762 reserved, never a real public domain"
    return "non-standard .bd suffix", f"unrecognized second-level label: .{second_last}.bd -- structurally valid .bd domain, verify manually whether it's a real registration"


def main():
    if not os.path.exists(MASTER_PATH):
        print(f"ERROR: {MASTER_PATH} not found.")
        sys.exit(1)

    with open(MASTER_PATH, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    category_counts = Counter()
    flagged_rows = []

    for row in rows:
        category, reason = classify(row["domain"])
        category_counts[category] += 1
        if category != "standard .bd suffix":
            flagged_rows.append({
                "domain": row["domain"],
                "category": category,
                "reason": reason,
                "source": row.get("source", ""),
                "sector": row.get("sector", ""),
            })

    print(f"Total domains checked: {len(rows)}\n")
    print("Breakdown:")
    for cat, n in category_counts.most_common():
        print(f"  {cat}: {n}")

    if flagged_rows:
        with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["domain", "category", "reason", "source", "sector"])
            writer.writeheader()
            writer.writerows(flagged_rows)
        print(f"\n{len(flagged_rows)} domains flagged for review -> {OUT_PATH}")
        print("\nSample of flagged domains:")
        for r in flagged_rows[:10]:
            print(f"  [{r['category']}] {r['domain']} -- {r['reason']}")
    else:
        print("\nNo anomalies found -- every domain genuinely ends in .bd with a recognized suffix.")


if __name__ == "__main__":
    main()
