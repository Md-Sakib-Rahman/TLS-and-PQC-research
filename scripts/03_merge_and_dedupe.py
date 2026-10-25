#!/usr/bin/env python3
"""
Merges every domain source under data/raw/ and data/interim/ into a single
deduplicated candidate list at data/processed/domains_master.csv.

This does NOT check DNS resolution or port-443 liveness -- it only merges and
dedupes names. Liveness checking is the next phase (not built yet).

Input sources read:
  - data/raw/crt_sh/*.json           (crt.sh JSON API responses)
  - data/interim/tranco_bd_*.txt     (pre-filtered Tranco .bd domains)
  - data/raw/sector_authority_lists/*.csv  (manually compiled authority lists,
    expected columns: domain,sector,source_name -- see sector_tag.py for the
    matching logic that also consumes these)

Output:
  data/processed/domains_master.csv with columns:
    domain, source, date_added
  (sector is filled in later by sector_tag.py, not here -- this script's only
  job is dedup, so it stays simple and auditable)
"""

import csv
import glob
import json
import os
import re
from datetime import date

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_CRTSH = os.path.join(BASE, "data", "raw", "crt_sh")
INTERIM = os.path.join(BASE, "data", "interim")
RAW_AUTHORITY = os.path.join(BASE, "data", "raw", "sector_authority_lists")
OUT_PATH = os.path.join(BASE, "data", "processed", "domains_master.csv")

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def clean(name: str) -> str:
    name = name.strip().lower()
    name = name.lstrip("*.")  # crt.sh wildcard certs (*.example.gov.bd)
    return name


def is_plausible_domain(name: str) -> bool:
    return bool(name) and bool(DOMAIN_RE.match(name)) and "bd" in name.split(".")[-2:]


def load_crtsh():
    found = {}
    for path in glob.glob(os.path.join(RAW_CRTSH, "*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                records = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"  SKIPPED {path}: {e}")
            continue
        for rec in records:
            raw_names = rec.get("name_value", "")
            for n in raw_names.split("\n"):
                n = clean(n)
                if is_plausible_domain(n):
                    found.setdefault(n, os.path.basename(path))
    print(f"crt.sh: {len(found)} plausible unique domains across {len(glob.glob(os.path.join(RAW_CRTSH, '*.json')))} file(s)")
    return found


def load_tranco():
    found = {}
    for path in glob.glob(os.path.join(INTERIM, "tranco_bd_*.txt")):
        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(",")
                name = clean(parts[-1]) if parts else ""
                if is_plausible_domain(name):
                    found.setdefault(name, os.path.basename(path))
    print(f"Tranco: {len(found)} unique .bd domains")
    return found


def load_authority_lists():
    found = {}
    for path in glob.glob(os.path.join(RAW_AUTHORITY, "*.csv")):
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = clean(row.get("domain", ""))
                if is_plausible_domain(name):
                    found.setdefault(name, os.path.basename(path))
    print(f"Sector authority lists: {len(found)} unique domains across {len(glob.glob(os.path.join(RAW_AUTHORITY, '*.csv')))} file(s)")
    return found


def main():
    all_sources = {}
    for loader in (load_crtsh, load_tranco, load_authority_lists):
        for domain, source in loader().items():
            # first source wins for provenance -- a domain seen in multiple
            # sources is still one row; provenance just records where it was
            # FIRST confirmed, since that's what matters for citing coverage
            all_sources.setdefault(domain, source)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    today = date.today().isoformat()
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "source", "date_added"])
        for domain in sorted(all_sources):
            writer.writerow([domain, all_sources[domain], today])

    print(f"\nTotal unique candidate domains: {len(all_sources)}")
    print(f"Written to {OUT_PATH}")
    print("\nNext: run sector_tag.py, then DNS-resolve and port-443-check before scanning.")


if __name__ == "__main__":
    main()
