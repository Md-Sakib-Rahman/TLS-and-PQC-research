#!/usr/bin/env python3
"""
Cleans the raw bangladesh-geocode JSON exports (divisions/districts/upazilas/
unions) into a single flat hierarchy CSV with a 'base_domain' column, in the
format verify_against_source_list.py expects (a column literally named
'base_domain' -- extra columns are fine, the script only reads that one).

Cleaning steps applied to each tier's 'url' field:
  1. Strip leading/trailing whitespace (6 rows in the raw data had it baked
     into the string, e.g. "chawgangaup.kishoreganj.gov.bd      ").
  2. Lowercase (domains are case-insensitive; raw data has inconsistent
     casing like "kagkandaUP.narayanganj.gov.bd").
  3. Strip a leading "www." if present. Only division/district rows carry
     it in the raw data (e.g. "www.comilla.gov.bd"); union/upazila rows
     never do. But the real-world/verified form of these sites elsewhere
     in this project (e.g. domains_master.csv, populated from Tranco) is
     bare -- "comilla.gov.bd", not "www.comilla.gov.bd". Left unstripped,
     every division/district row would carry a www. prefix its real
     counterpart doesn't have, so an otherwise-correct exact-domain match
     would silently fail on a formatting difference, not a real absence.
  4. Prefix with https:// to form the 'url' column. 'base_domain' stays
     bare (no scheme), matching the convention already used in
     gov_national_portal.csv / universities_ugc.csv. Unlike those files,
     base_domain here is the FULL domain, not a 3-label reduction -- see
     base_domain_of() below for why.
  5. Dedupe: where the same cleaned url appears on more than one row
     (16 distinct urls, at the union tier), keep only the first row and
     drop the rest -- this affects more than 16 rows since some urls repeat
     more than twice; the actual dropped-row count is reported below.
  6. Domains ending in .bdgovportal.com (not .gov.bd) are NOT dropped, but
     marked with category=bdgovportal_flagged instead of category=gov_bd,
     so they can be excluded from downstream verification without losing
     the row.
  7. 3 upazila rows have the literal string "null" as their url (a missing-
     data sentinel from the source repo, not a real domain: Eidgaon,
     Madhyanagar, Dasar). These are NOT treated as bdgovportal and are NOT
     given a fabricated "https://null" url/base_domain -- they get
     category=missing_url and empty url/base_domain fields instead, so
     they aren't silently miscounted as either verified or flagged-portal.

Source data: cloned from https://github.com/nuhil/bangladesh-geocode
"""

import csv
import json
import os

REPO = "/tmp/claude-1000/-home-voyager1-Documents-Researches-bd-tls-pqc-study/e4bbeba9-5f9a-4476-82d3-59697cdb7dbc/scratchpad/bangladesh-geocode"
OUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "raw", "sector_authority_lists", "gov_hierarchy.csv",
)

TIERS = [
    ("division", os.path.join(REPO, "divisions", "divisions.json"), None),
    ("district", os.path.join(REPO, "districts", "districts.json"), "division_id"),
    ("upazila", os.path.join(REPO, "upazilas", "upazilas.json"), "district_id"),
    ("union", os.path.join(REPO, "unions", "unions.json"), "upazilla_id"),
]


def load_table(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    for item in doc:
        if item.get("type") == "table":
            return item["data"]
    raise ValueError(f"no 'table' entry found in {path}")


def base_domain_of(url: str) -> str:
    """
    The full cleaned domain, unchanged -- NOT the last-3-labels reduction that
    verify_against_source_list.py's own extract_base_domain() applies.

    That 3-label heuristic is correct for institutions like universities,
    where "mail.iiuc.ac.bd" really is a subdomain of the institution
    "iiuc.ac.bd". It is WRONG here: Bangladesh's union/upazila government
    sites (e.g. "subilup.comilla.gov.bd") are not subdomains of the district
    site "comilla.gov.bd" -- the extra label IS the institution identity.
    Applying the 3-label rule while building this source list collapsed all
    ~4,500 union/upazila domains down to their shared district domain
    (confirmed: printing the loaded base domains showed only ~64
    district/division-level values, not thousands of distinct entities).
    Each row's base_domain must stay the full domain so union/upazila
    entities remain individually matchable.
    """
    return url


def main():
    rows = []
    for tier, path, parent_key in TIERS:
        for rec in load_table(path):
            raw_url = rec["url"]
            clean_url = raw_url.strip().lower()
            had_www = clean_url.startswith("www.")
            if had_www:
                clean_url = clean_url[len("www."):]
            if clean_url == "null":
                rows.append({
                    "tier": tier,
                    "id": rec["id"],
                    "parent_id": rec.get(parent_key, "") if parent_key else "",
                    "name": rec["name"],
                    "bn_name": rec["bn_name"],
                    "url": "",
                    "base_domain": "",
                    "category": "missing_url",
                    "raw_url_had_whitespace": False,
                    "raw_url_had_www": False,
                })
                continue
            rows.append({
                "tier": tier,
                "id": rec["id"],
                "parent_id": rec.get(parent_key, "") if parent_key else "",
                "name": rec["name"],
                "bn_name": rec["bn_name"],
                "url": f"https://{clean_url}",
                "base_domain": base_domain_of(clean_url),
                "category": "gov_bd" if clean_url.endswith(".gov.bd") else "bdgovportal_flagged",
                "raw_url_had_whitespace": raw_url != raw_url.strip(),
                "raw_url_had_www": had_www,
            })

    total_before_dedupe = len(rows)

    # Dedupe on cleaned url (not base_domain -- two different real offices
    # could share a base_domain legitimately; only exact url repeats are junk).
    # missing_url rows are exempt: they all share url="" and are not real
    # duplicates of each other.
    seen = {}
    deduped = []
    dropped = []
    for row in rows:
        if row["category"] == "missing_url":
            deduped.append(row)
            continue
        key = row["url"]
        if key in seen:
            dropped.append(row)
            continue
        seen[key] = row
        deduped.append(row)

    distinct_dupe_urls = len({r["url"] for r in dropped})

    fieldnames = ["tier", "id", "parent_id", "name", "bn_name", "url",
                  "base_domain", "category", "raw_url_had_whitespace", "raw_url_had_www"]
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(deduped)

    by_tier = {}
    for row in deduped:
        by_tier[row["tier"]] = by_tier.get(row["tier"], 0) + 1

    flagged = sum(1 for r in deduped if r["category"] == "bdgovportal_flagged")
    missing = sum(1 for r in deduped if r["category"] == "missing_url")
    whitespace_fixed = sum(1 for r in rows if r["raw_url_had_whitespace"])
    www_stripped = sum(1 for r in rows if r["raw_url_had_www"])

    print(f"Rows before dedupe: {total_before_dedupe}")
    print(f"Distinct duplicate urls collapsed: {distinct_dupe_urls}")
    print(f"Rows dropped as duplicates: {len(dropped)}")
    print(f"Rows after dedupe: {len(deduped)}")
    print(f"Rows with whitespace stripped from url: {whitespace_fixed}")
    print(f"Rows with leading www. stripped from url: {www_stripped}")
    print(f"Rows flagged bdgovportal_flagged (not dropped): {flagged}")
    print(f"Rows flagged missing_url (literal 'null' in source, not dropped): {missing}")
    print(f"By tier: {by_tier}")
    print(f"\nWrote {OUT_PATH}")


if __name__ == "__main__":
    main()
