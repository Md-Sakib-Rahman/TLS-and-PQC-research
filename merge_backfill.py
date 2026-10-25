#!/usr/bin/env python3
"""
Merges backfilled HTTP results from a secondary vantage point (standalone_probe.py, run on a
different network) into the real http.jsonl for a given run.

WHAT IT DOES (safe to re-run; one deterministic result per domain)
  For every domain on --ip, the final http.jsonl keeps exactly ONE record, chosen in this order:
    1. an 'ok' record from the backfill file (newest data wins)
    2. otherwise an existing 'ok' record already in http.jsonl (e.g. an earlier backfill batch --
       these are KEPT, never wiped, so batches can be merged one after another)
    3. otherwise, only with --include-failures, the backfill's non-ok record (a real "scanned
       and failed" result, e.g. timeout / empty_response), tagged with its source
    4. otherwise nothing -- the domain stays absent, i.e. "pending", and a future b2 resume
       will retry it
  Existing non-ok records for the cluster (stale timeouts from the rate-limited b2 attempts)
  are always dropped: they reflect the block, not the servers.
  Records for other IPs are never touched. Every backfill record gets
  "source": "secondary_vantage" plus the same hsts/waf/family fields b2 computes.

Usage (from project root):
    python merge_backfill.py --run-id run_2026-09-19 --ip 103.157.135.180 --backfill results.jsonl
    python merge_backfill.py ... --include-failures     # final batch: keep real failures too
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from measurement.common.io_utils import PROCESSED_DIR, resolve_run_dir, utc_now
from measurement.phase_b_tls import http_probe as H


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--ip", required=True, help="the shared-hosting IP being backfilled")
    ap.add_argument("--backfill", required=True, help="path to the results.jsonl from standalone_probe.py")
    ap.add_argument("--include-failures", action="store_true",
                    help="write backfill non-ok records when no ok record exists (final batch)")
    args = ap.parse_args()

    run_dir = resolve_run_dir(args.run_id)
    http_path = os.path.join(run_dir, "raw", "http.jsonl")
    live_path = os.path.join(PROCESSED_DIR, "live_domains.csv")

    import csv
    family = {}
    with open(live_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["ip"] == args.ip:
                family[r["domain"]] = r.get("family")
    if not family:
        sys.exit(f"ERROR: no domains found with ip == {args.ip} in {live_path}")
    cluster = set(family)
    print(f"Cluster: {len(cluster)} domains on {args.ip}")

    other_lines, existing_ok, dropped_stale = [], {}, 0
    if os.path.exists(http_path):
        with open(http_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    other_lines.append(line)
                    continue
                d = rec.get("domain")
                if d not in cluster:
                    other_lines.append(line)
                elif rec.get("status") == "ok":
                    if d not in existing_ok or (rec.get("ts") or "") >= (existing_ok[d].get("ts") or ""):
                        existing_ok[d] = rec
                else:
                    dropped_stale += 1

    def enrich(rec):
        headers = rec.get("headers") or {}
        ok = rec.get("status") == "ok"
        return {"domain": rec["domain"], "ip": rec["ip"], "family": family.get(rec["domain"]),
                "ts": rec.get("ts", utc_now()), "status": rec.get("status"),
                "http_version": rec.get("http_version"), "status_code": rec.get("status_code"),
                "reason": rec.get("reason"), "headers": headers,
                "error": rec.get("error"),
                "hsts": H.parse_hsts(headers) if ok else None,
                "waf": H.detect_waf(headers) if ok else None,
                "source": "secondary_vantage"}

    backfill_ok, backfill_fail = {}, {}
    with open(args.backfill, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            d = rec.get("domain")
            if d not in cluster:
                continue
            (backfill_ok if rec.get("status") == "ok" else backfill_fail)[d] = rec

    final, counts = [], {"backfill_ok": 0, "kept_existing_ok": 0, "backfill_failure": 0, "pending": 0}
    for d in sorted(cluster):
        if d in backfill_ok:
            final.append(json.dumps(enrich(backfill_ok[d]))); counts["backfill_ok"] += 1
        elif d in existing_ok:
            final.append(json.dumps(existing_ok[d])); counts["kept_existing_ok"] += 1
        elif args.include_failures and d in backfill_fail:
            final.append(json.dumps(enrich(backfill_fail[d]))); counts["backfill_failure"] += 1
        else:
            counts["pending"] += 1

    with open(http_path, "w", encoding="utf-8") as f:
        f.write("\n".join(other_lines + final) + "\n")

    print(f"Dropped {dropped_stale} stale non-ok record(s) for this cluster")
    print(f"Result for the {len(cluster)} cluster domains: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    if backfill_fail and not args.include_failures:
        print(f"Note: {len(backfill_fail)} backfill failures left pending; pass --include-failures to record them.")

    present = set()
    with open(http_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                present.add(json.loads(line).get("domain"))
    print(f"http.jsonl now covers {len(present & cluster)}/{len(cluster)} cluster domains "
          f"({len(present)} domains in total). Wrote: {http_path}")


if __name__ == "__main__":
    main()