#!/usr/bin/env python3
"""
Phase A, step 3: join corpus + DNS results + port-443 results.

Outputs (data/measurement/processed/):
  liveness_all.csv   one row per corpus domain, with every Phase A status
  live_domains.csv   ONLY domains that resolve AND accept TCP on 443 -- the input to Phase B

dns_status values:
  resolves      has an A or AAAA record
  nxdomain      name does not exist
  no_address    name exists but has no A/AAAA
  inconclusive  timeout / SERVFAIL / error (NOT counted as dead)
  not_scanned   in the corpus but absent from dns.jsonl (run incomplete)

port443 values: open | closed | no_response | not_scanned (resolves but a2 hasn't reached it)
                | n/a (does not resolve, so never tested)

Usage: python measurement/phase_a_liveness/a3_build_live_list.py [--run-id ID]
"""

import argparse
import csv
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.corpus import load_corpus, sector_category, verification_tier
from measurement.common.io_utils import (INPUT_DIR, PROCESSED_DIR, read_jsonl, read_run_meta,
                                         resolve_run_dir)

ALL_COLS = ["domain", "sector", "category", "tier", "dns_status", "has_mx", "ds_present",
            "dnskey_present", "ad_validated", "port443", "live", "ip", "family"]


def dns_status(rec):
    if rec["resolves"]:
        return "resolves"
    a, aaaa = rec["A"]["status"], rec.get("AAAA", {}).get("status")
    if a == "nxdomain":
        return "nxdomain"
    if a == "nodata" and aaaa == "nodata":
        return "no_address"
    return "inconclusive"


def ok(rec, rtype):
    return rec.get(rtype, {}).get("status") == "ok"


def build_row(corpus_row, dns_rec, p443_rec):
    d = corpus_row["domain"]
    base = {"domain": d, "sector": corpus_row["sector"], "category": sector_category(corpus_row["sector"]),
            "tier": verification_tier(corpus_row["sector"])}
    if dns_rec is None:
        return {**base, "dns_status": "not_scanned", "has_mx": "", "ds_present": "", "dnskey_present": "",
                "ad_validated": "", "port443": "n/a", "live": False, "ip": "", "family": ""}
    status = dns_status(dns_rec)
    row = {**base, "dns_status": status, "has_mx": ok(dns_rec, "MX"), "ds_present": ok(dns_rec, "DS"),
           "dnskey_present": ok(dns_rec, "DNSKEY"),
           "ad_validated": bool(dns_rec["A"].get("ad") or dns_rec.get("AAAA", {}).get("ad"))}
    if status != "resolves":
        return {**row, "port443": "n/a", "live": False, "ip": "", "family": ""}
    if p443_rec is None:
        return {**row, "port443": "not_scanned", "live": False, "ip": "", "family": ""}
    return {**row, "port443": p443_rec["port443"], "live": p443_rec["port443"] == "open",
            "ip": p443_rec.get("ip") or "", "family": p443_rec.get("family") or ""}


def write_csv(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", help="run folder (default: newest)")
    args = ap.parse_args()

    run_dir = resolve_run_dir(args.run_id)
    meta = read_run_meta(run_dir)
    corpus = load_corpus(os.path.join(INPUT_DIR, meta["input"]["file"]))
    dns = {r["domain"]: r for r in read_jsonl(os.path.join(run_dir, "raw", "dns.jsonl"))}
    p443 = {r["domain"]: r for r in read_jsonl(os.path.join(run_dir, "raw", "port443.jsonl"))}

    rows = [build_row(c, dns.get(c["domain"]), p443.get(c["domain"])) for c in corpus]
    live = [r for r in rows if r["live"]]

    os.makedirs(PROCESSED_DIR, exist_ok=True)
    write_csv(os.path.join(PROCESSED_DIR, "liveness_all.csv"), ALL_COLS, rows)
    write_csv(os.path.join(PROCESSED_DIR, "live_domains.csv"), ["domain", "sector", "category", "tier", "ip", "family"], live)

    print(f"Run: {os.path.basename(run_dir)} | corpus rows: {len(rows)}")
    for k, v in sorted(Counter(r["dns_status"] for r in rows).items()):
        print(f"  dns_status  {k:13s} {v}")
    for k, v in sorted(Counter(r["port443"] for r in rows).items()):
        print(f"  port443     {k:13s} {v}")
    print(f"Live (resolves + 443 open): {len(live)}")
    n_ns = sum(r["dns_status"] == "not_scanned" for r in rows)
    n_ps = sum(r["port443"] == "not_scanned" for r in rows)
    if n_ns or n_ps:
        print(f"WARNING: run incomplete -- {n_ns} domains lack DNS results, {n_ps} resolving domains lack port-443 results.")
    print(f"Wrote: {PROCESSED_DIR}/liveness_all.csv, live_domains.csv")


if __name__ == "__main__":
    main()
