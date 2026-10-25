#!/usr/bin/env python3
"""
Reclassifies domains in data/processed/domains_master.csv that are currently
tagged 'commercial (heuristic)' or 'unclassified' into 'banking (keyword
match -- verify manually)' or 'telecom (keyword match -- verify manually)'
based on known Bangladesh Bank scheduled-bank names and BTRC-licensed mobile
operator names.

WHY THIS EXISTS: suffix heuristics alone (.com.bd -> "commercial") cannot
distinguish a bank from an e-commerce site or anything else under .com.bd --
every scheduled bank in Bangladesh operates under .com.bd, not a dedicated
suffix. This script exists specifically to recover the banking sector that
sector_tag.py's suffix-only pass cannot see. Source for bank/operator names:
Wikipedia "List of banks in Bangladesh" (citing Bangladesh Bank's own
"Financial System" page, bb.org.bd) and BTRC's published operator list --
see docs/Reference_List.docx / Research_Proposal.docx sources [1]-[18] for
the sector authority sourcing this study relies on generally.

THIS IS A HEURISTIC, NOT GROUND TRUTH. A keyword match means "this domain
CONTAINS a bank/operator name" -- it does not confirm the domain is the
bank's real, official site (a lookalike or unrelated domain could also
match). Every match must be manually checked against bb.org.bd/btrc.gov.bd
before being treated as confirmed in the coverage report. That manual check
IS the "collect sector_authority_lists" step the README already calls for --
this script only narrows down what needs checking, from ~1,300+ commercial
domains down to a much smaller candidate list.

Output: 
  - Updates data/processed/domains_master.csv in place (sector column)
  - Writes data/processed/banking_telecom_review.csv -- the candidate list
    for manual verification
"""

import csv
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_PATH = os.path.join(BASE, "data", "processed", "domains_master.csv")
REVIEW_PATH = os.path.join(BASE, "data", "processed", "banking_telecom_review.csv")

# Keywords derived from scheduled bank names (Wikipedia "List of banks in
# Bangladesh", sourced to Bangladesh Bank's own "Financial System" listing).
# Lowercased, stripped of generic words ("bank", "plc", "limited") so a
# keyword like "sonali" matches "sonalibank.com.bd", "sonali-bank.com.bd",
# etc. regardless of exact formatting.
BANK_KEYWORDS = [
    # State-owned commercial banks
    "sonali", "janata", "agrani", "rupali", "basic", "bdbl",
    # Specialized banks
    "krishi", "probashikollyan", "probashi-kollyan",
    # Private commercial banks (conventional)
    "abbank", "bangladeshcommerce", "bankasia", "bengalcommercial",
    "bracbank", "citizensbank", "citybank", "communitybank",
    "dhakabank", "dutchbangla", "dbbl", "easternbank", "ificbank",
    "jamunabank", "meghnabank", "mercantilebank", "midlandbank",
    "modhumotibank", "mutualtrustbank", "mtb", "nationalbank",
    "nccbank", "nrbbank", "nrbcbank", "onebank", "padmabank",
    "primebank", "pubalibank", "sbacbank", "shimantobank",
    "southeastbank", "premierbank", "trustbank", "ucb",
    "unitedcommercial", "uttarabank",
    # Islami Shariah-based PCBs
    "islamibank", "alarafah", "eximbank", "firstsecurityislami",
    "globalislami", "icbislamic", "shahjalalislami", "socialislami",
    # Foreign commercial banks
    "alfalah", "citibank", "combank", "habibbank", "hsbc",
    "standardchartered", "sbi", "wooribank",
]

TELECOM_KEYWORDS = [
    "grameenphone", "gpbd", "robi", "banglalink", "teletalk",
]

# Generic "bank" substring as a lower-confidence fallback -- catches names
# not in the explicit list above (e.g. a merged/renamed entity), but is more
# prone to false positives (e.g. a domain that merely mentions "bank" in an
# unrelated sense). Flagged separately in the review CSV so it gets extra
# scrutiny, not silently trusted like a named match.
GENERIC_BANK_PATTERN = re.compile(r"bank", re.IGNORECASE)

RECLASSIFIABLE_SECTORS = {
    "commercial (heuristic -- review manually)",
    "unclassified",
}


def strip_noise(domain: str) -> str:
    return domain.lower().replace("-", "").replace(".", "")


def classify(domain: str):
    flat = strip_noise(domain)
    for kw in BANK_KEYWORDS:
        if kw in flat:
            return "banking (keyword match -- verify manually)", f"matched keyword: {kw}"
    for kw in TELECOM_KEYWORDS:
        if kw in flat:
            return "telecom (keyword match -- verify manually)", f"matched keyword: {kw}"
    if GENERIC_BANK_PATTERN.search(domain):
        return "banking (LOW CONFIDENCE -- generic 'bank' substring only)", "generic 'bank' substring, not a named match"
    return None, None


def main():
    if not os.path.exists(MASTER_PATH):
        print(f"ERROR: {MASTER_PATH} not found. Run merge_and_dedupe.py and sector_tag.py first.")
        return

    with open(MASTER_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    review_rows = []
    reclassified_count = 0

    for row in rows:
        if row.get("sector") not in RECLASSIFIABLE_SECTORS:
            continue
        new_sector, reason = classify(row["domain"])
        if new_sector:
            old_sector = row["sector"]
            row["sector"] = new_sector
            reclassified_count += 1
            review_rows.append({
                "domain": row["domain"],
                "old_sector": old_sector,
                "new_sector": new_sector,
                "match_reason": reason,
                "verified_against_official_list": "",  # fill in manually: Y/N
            })

    with open(MASTER_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with open(REVIEW_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "old_sector", "new_sector", "match_reason", "verified_against_official_list"])
        writer.writeheader()
        writer.writerows(review_rows)

    from collections import Counter
    breakdown = Counter(r["sector"] for r in rows)
    print(f"Reclassified {reclassified_count} domains out of the 'commercial'/'unclassified' pool.")
    print(f"Candidate list for manual verification written to: {REVIEW_PATH}")
    print("\nFull updated sector breakdown:")
    for sector, n in breakdown.most_common():
        print(f"  {sector}: {n}")

    low_conf = breakdown.get("banking (LOW CONFIDENCE -- generic 'bank' substring only)", 0)
    if low_conf:
        print(f"\n{low_conf} domains matched ONLY the generic 'bank' substring, not a named bank --")
        print("these need the most scrutiny in banking_telecom_review.csv before being trusted.")

    print("\nNEXT STEP (unavoidable, no script can do this part): open")
    print(f"  {REVIEW_PATH}")
    print("and check each domain against bb.org.bd (banks) or btrc.gov.bd (telecom) directly --")
    print("this script found CANDIDATES, it did not confirm official status.")


if __name__ == "__main__":
    main()