#!/usr/bin/env python3
"""
Phase B, step 1: TLS / post-quantum handshake scan of every live domain.

Input:  data/measurement/processed/live_domains.csv (Phase A output) for the given --run-id.
        Before scanning, the live list is checked against that run's port443.jsonl (same domain
        set) so the input can't silently come from a different run.
Output: data/measurement/runs/<run_id>/raw/tls.jsonl (append-only, resumable), one record per domain.

What is measured, and why each probe exists, is documented in tls_probe.py. In short:
  default (browser-like, offers X25519MLKEM768) -> classical / legacy fallbacks only on failure
  -> pqc_only (six PQ groups) only when the server chose a classical group under TLS 1.3
  -> old_versions (TLS 1.0-1.1 ONLY) always, for every domain TCP reaches -- reports whether the
     server still accepts an old version even when its best version is higher (see tls_probe.py).
Every handshake uses SNI = the domain and connects to the IP recorded in Phase A. Most domains
therefore get 2 handshakes (default + old_versions); domains needing PQ or fallback probing get more.

Safety / politeness:
  - max_per_ip simultaneous handshakes to any one IP (1,217 domains share one host)
  - max_cps new connections per second overall
  - no application data is sent; connections are closed right after the handshake

Pre-flight (aborts on failure):
  1. library self-test: bundled OpenSSL must support X25519MLKEM768 and group readback
  2. positive control: a host known to serve hybrid PQ by default must negotiate ML-KEM with a
     trusted certificate. Catches a broken library, a network path that drops large ClientHellos,
     and TLS-intercepting proxies. --skip-control exists for tests only.

Usage (from project root):
    python measurement/phase_b_tls/b1_tls_handshake_scan.py --run-id run_2026-09-19 --limit 100   # smoke
    python measurement/phase_b_tls/b1_tls_handshake_scan.py --run-id run_2026-09-19                # full
"""

import argparse
import csv
import hashlib
import os
import random
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import (PROCESSED_DIR, JsonlWriter, done_keys, load_config, read_jsonl,
                                         resolve_run_dir, update_run_meta, utc_now)
from measurement.common.net_utils import Gate
from measurement.phase_b_tls import tls_probe

PORT = 443


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_live(run_dir, live_path):
    with open(live_path, newline="", encoding="utf-8") as f:
        live = list(csv.DictReader(f))
    open_in_run = {r["domain"] for r in read_jsonl(os.path.join(run_dir, "raw", "port443.jsonl"))
                   if r.get("port443") == "open"}
    listed = {r["domain"] for r in live}
    if listed != open_in_run:
        sys.exit(f"ERROR: {live_path} does not match this run's port-443 results "
                 f"({len(listed)} listed vs {len(open_in_run)} open in run; "
                 f"{len(listed - open_in_run)} extra, {len(open_in_run - listed)} missing).\n"
                 f"Re-run a3_build_live_list.py --run-id {os.path.basename(run_dir)} first.")
    bad = [r["domain"] for r in live if not r.get("ip")]
    if bad:
        sys.exit(f"ERROR: {len(bad)} live domains have no IP recorded (e.g. {bad[:3]}).")
    return live


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True, help="Phase A run folder whose live list is scanned")
    ap.add_argument("--limit", type=int, help="only N domains (smoke test; random but fixed sample)")
    ap.add_argument("--config", help="alternate config.yaml")
    ap.add_argument("--skip-control", action="store_true", help="skip the positive PQ control (tests only)")
    ap.add_argument("--trust-store", help="PEM bundle for validation (default: certifi / Mozilla roots)")
    args = ap.parse_args()

    cfg = load_config(args.config)["tls"]
    run_dir = resolve_run_dir(args.run_id)
    live_path = os.path.join(PROCESSED_DIR, "live_domains.csv")
    out_path = os.path.join(run_dir, "raw", "tls.jsonl")

    try:
        versions = tls_probe.selftest()
    except Exception as e:
        sys.exit(f"ERROR: library self-test failed: {e}")
    ctxs = tls_probe.build_contexts()
    store, trust_info = tls_probe.load_trust_store_with_info(args.trust_store)
    trust_info["sha256"] = sha256_file(trust_info["path"])
    if not args.trust_store:
        import certifi
        trust_info["certifi"] = certifi.__version__

    live = load_live(run_dir, live_path)
    if args.limit:
        live = random.Random(7).sample(live, min(args.limit, len(live)))   # spread over hosts, not one cluster
    done = done_keys(out_path)
    todo = [r for r in live if r["domain"] not in done]
    print(f"Run: {os.path.basename(run_dir)}\nLibrary: {versions['bundled_openssl']} via pyOpenSSL {versions['pyopenssl']}"
          f" / cryptography {versions['cryptography']}\nPQ groups offered in pqc_only: {', '.join(versions['pqc_groups_offered'])}"
          f"\nTrust store: {trust_info['roots_loaded']} roots loaded, {trust_info['roots_skipped']} skipped"
          f"\nLive domains {len(live)} | already done {len(done)} | to do {len(todo)}")

    meta = {"config": cfg, "started": utc_now(), "libraries": versions, "groups": ctxs["_groups"],
            "trust_store": trust_info, "input": {"file": live_path, "sha256": sha256_file(live_path)},
            "control": "skipped"}
    if todo and not args.skip_control:
        results, ok = tls_probe.control_check(cfg["control_hosts"], ctxs, store, PORT, cfg["timeout_s"])
        meta["control"] = results
        if not ok:
            update_run_meta(run_dir, "tls", meta)
            sys.exit("ERROR: positive control failed -- no control host negotiated an ML-KEM group with a trusted "
                     f"certificate:\n{results}\nPossible causes: no internet, a network path that drops large "
                     "ClientHellos, a TLS-intercepting proxy, or the control hosts changed. Do not scan until resolved.")
        print("Control check passed: " + "; ".join(f"{h}: {r.get('group')} trusted={r.get('trusted')}" for h, r in results.items()))
    update_run_meta(run_dir, "tls", meta)

    gate = Gate(cfg["max_per_ip"], cfg["max_cps"])
    writer, tally, old_tls_tally = JsonlWriter(out_path), Counter(), Counter()
    by_domain = {r["domain"]: r for r in todo}
    try:
        with ThreadPoolExecutor(max_workers=cfg["workers"]) as pool:
            futures = {pool.submit(tls_probe.scan_domain, r["domain"], r["ip"], ctxs, store, PORT,
                                   cfg["timeout_s"], gate): r["domain"] for r in todo}
            for i, fut in enumerate(as_completed(futures), 1):
                d = futures[fut]
                try:
                    rec = fut.result()
                except Exception as e:                           # never lose a domain silently
                    rec = {"domain": d, "ip": by_domain[d]["ip"], "status": "error",
                           "error": f"{type(e).__name__}: {e}"[:200]}
                rec["ts"], rec["family"] = utc_now(), by_domain[d].get("family")
                writer.write(rec)
                tally[rec.get("pq_class", rec["status"])] += 1
                old_tls_tally[rec.get("accepts_tls_1_0_or_1_1")] += 1
                if i % 250 == 0 or i == len(todo):
                    print(f"  {i}/{len(todo)}  " + "  ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    except KeyboardInterrupt:
        print("\nInterrupted -- progress is saved; re-run the same command to resume.")
        sys.exit(1)
    finally:
        writer.close()

    update_run_meta(run_dir, "tls", {**meta, "finished": utc_now(), "scanned_this_session": len(todo)})
    print(f"Accepts TLS 1.0/1.1 (independent of best version): True={old_tls_tally[True]}  "
          f"False={old_tls_tally[False]}  unknown/skipped={old_tls_tally[None]}")
    print(f"Done. Output: {out_path}")


if __name__ == "__main__":
    main()