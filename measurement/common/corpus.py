#!/usr/bin/env python3
"""
Frozen, hash-checked copy of the domain corpus for measurement runs.

Measurement NEVER reads or writes data/processed/domains_master.csv directly.
It works from a dated frozen copy plus a .sha256 file, so every result can be
traced to the exact corpus it was measured against.

Usage (from project root):
    python measurement/common/corpus.py freeze      # copy domains_master.csv -> frozen copy
"""

import csv
import datetime
import glob
import hashlib
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import BASE, INPUT_DIR

MASTER = os.path.join(BASE, "data", "processed", "domains_master.csv")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def freeze(src=MASTER):
    os.makedirs(INPUT_DIR, exist_ok=True)
    dest = os.path.join(INPUT_DIR, f"domains_frozen_{datetime.date.today().isoformat()}.csv")
    if os.path.exists(dest):
        sys.exit(f"ERROR: {dest} already exists. Frozen copies are never overwritten.")
    shutil.copyfile(src, dest)
    digest = sha256_of(dest)
    with open(dest + ".sha256", "w") as f:
        f.write(digest + "\n")
    return dest, digest


def latest_frozen():
    files = sorted(glob.glob(os.path.join(INPUT_DIR, "domains_frozen_*.csv")))
    if not files:
        sys.exit("ERROR: no frozen corpus found. Run: python measurement/common/corpus.py freeze")
    return files[-1]


def load_corpus(path):
    """Returns list of dict rows. Verifies the .sha256 file if present."""
    sha_path = path + ".sha256"
    if os.path.exists(sha_path):
        expected = open(sha_path).read().strip()
        if sha256_of(path) != expected:
            sys.exit(f"ERROR: {path} does not match its .sha256 -- the frozen corpus was modified.")
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["domain"] = r["domain"].strip().lower().rstrip(".")
    return rows


def sector_category(sector: str) -> str:
    """'government (institution-verified)' -> 'government'"""
    return sector.split(" (")[0].strip()


def verification_tier(sector: str) -> str:
    s = sector.lower()
    if "rejected" in s:                                   # check first: also contains 'keyword match'
        return "rejected"
    if "institution-verified" in s or "source-verified" in s:
        return "verified"
    return "unverified"


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "freeze":
        dest, digest = freeze()
        rows = load_corpus(dest)
        print(f"Frozen: {dest}\nRows:   {len(rows)}\nSHA256: {digest}")
    else:
        print(__doc__)
