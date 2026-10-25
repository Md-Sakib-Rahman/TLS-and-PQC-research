#!/usr/bin/env python3
"""
Phase B, step 2: HTTP response header collection over HTTPS -- HSTS presence and passive
WAF vendor signature detection. What each field means, and the (significant) limitations
of passive header-based WAF detection, are documented in http_probe.py.

Input:  data/measurement/processed/live_domains.csv for the given --run-id, cross-checked
        against that run's port443.jsonl (same rule b1 uses, so b1 and b2 are guaranteed to
        have scanned the identical domain set even if run independently or resumed at
        different times).
Output: data/measurement/runs/<run_id>/raw/http.jsonl (append-only, resumable).

One GET / per domain, ALPN restricted to http/1.1, redirects NOT followed (see http_probe.py).
Politeness: same Gate design as b1 -- max_per_ip simultaneous connections to any one IP,
max_cps connections/second overall.

Pre-flight (aborts on failure):
  - REQUIRES the User-Agent in config.yaml's http.user_agent to be filled in with a real
    contact URL/email; refuses to run against the live corpus with the placeholder value.
    (--skip-ua-check exists for tests only.)
  - Positive control: a known Cloudflare-fronted host must show the Cloudflare header
    signature. Catches a network path that strips or rewrites headers. --skip-control for tests.

Usage (from project root):
    python measurement/phase_b_tls/b2_collect_http_headers.py --run-id run_2026-09-19 --limit 100
    python measurement/phase_b_tls/b2_collect_http_headers.py --run-id run_2026-09-19
"""

import argparse
import csv
import hashlib
import os
import random
import ssl
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import (PROCESSED_DIR, JsonlWriter, done_keys, load_config, read_jsonl,
                                         resolve_run_dir, update_run_meta, utc_now)
from measurement.common.net_utils import Gate
from measurement.phase_b_tls import http_probe

PORT = 443
UA_PLACEHOLDER_MARKER = "FILL-IN"


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
    ap.add_argument("--skip-control", action="store_true", help="skip the positive header control (tests only)")
    ap.add_argument("--skip-ua-check", action="store_true", help="allow the placeholder User-Agent (tests only)")
    args = ap.parse_args()

    cfg = load_config(args.config)["http"]
    if not args.skip_ua_check and UA_PLACEHOLDER_MARKER in cfg["user_agent"]:
        sys.exit(f"ERROR: measurement/config.yaml's http.user_agent is still the placeholder.\n"
                 f"This is the first script that makes a request a server operator could log --"
                 f" identify the study with a real contact URL/email before scanning the live corpus.")

    run_dir = resolve_run_dir(args.run_id)
    live_path = os.path.join(PROCESSED_DIR, "live_domains.csv")
    out_path = os.path.join(run_dir, "raw", "http.jsonl")

    ctx = http_probe.build_context()
    live = load_live(run_dir, live_path)
    if args.limit:
        live = random.Random(7).sample(live, min(args.limit, len(live)))   # same seed/spread as b1
    done = done_keys(out_path)
    todo = [r for r in live if r["domain"] not in done]
    print(f"Run: {os.path.basename(run_dir)}\nMin TLS version requested: {ctx.min_tls_version_requested}"
          f"\nUser-Agent: {cfg['user_agent']}"
          f"\nLive domains {len(live)} | already done {len(done)} | to do {len(todo)}")

    meta = {"config": {k: v for k, v in cfg.items()}, "started": utc_now(),
            "python_ssl": ssl.OPENSSL_VERSION, "control": "skipped",
            "input": {"file": live_path, "sha256": sha256_file(live_path)}}
    if todo and not args.skip_control:
        results, ok = http_probe.control_check(cfg["control_hosts"], ctx, PORT, cfg["timeout_s"])
        meta["control"] = results
        if not ok:
            update_run_meta(run_dir, "http", meta)
            sys.exit(f"ERROR: positive control failed -- no control host showed its known WAF/CDN header "
                     f"signature:\n{results}\nPossible causes: no internet, or a network path that strips "
                     f"or rewrites response headers (a proxy). Do not scan until resolved.")
        print("Control check passed: " + "; ".join(
            f"{h}: waf={r.get('waf', {}).get('vendors')}" for h, r in results.items()))
    update_run_meta(run_dir, "http", meta)

    gate = Gate(cfg["max_per_ip"], cfg["max_cps"])
    writer, tally, hsts_tally, waf_tally = JsonlWriter(out_path), Counter(), Counter(), Counter()
    by_domain = {r["domain"]: r for r in todo}

    def scan_one(r):
        with gate(r["ip"]):
            return http_probe.probe_domain(r["domain"], r["ip"], PORT, cfg["timeout_s"], cfg["user_agent"],
                                           ctx, cfg["max_header_bytes"])

    try:
        with ThreadPoolExecutor(max_workers=cfg["workers"]) as pool:
            futures = {pool.submit(scan_one, r): r["domain"] for r in todo}
            for i, fut in enumerate(as_completed(futures), 1):
                d = futures[fut]
                try:
                    rec = fut.result()
                except Exception as e:
                    rec = {"domain": d, "ip": by_domain[d]["ip"], "status": "error",
                           "error": f"{type(e).__name__}: {e}"[:200], "hsts": None, "waf": None}
                rec["ts"], rec["family"] = utc_now(), by_domain[d].get("family")
                writer.write(rec)
                tally[rec["status"]] += 1
                hsts_tally[rec["hsts"]["present"] if rec.get("hsts") else None] += 1
                if rec.get("waf"):
                    for v in (rec["waf"]["vendors"] or ["(none)"]):
                        waf_tally[v] += 1
                if i % 250 == 0 or i == len(todo):
                    print(f"  {i}/{len(todo)}  " + "  ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    except KeyboardInterrupt:
        print("\nInterrupted -- progress is saved; re-run the same command to resume.")
        sys.exit(1)
    finally:
        writer.close()

    update_run_meta(run_dir, "http", {**meta, "finished": utc_now(), "scanned_this_session": len(todo)})
    print(f"HSTS present: True={hsts_tally[True]}  False={hsts_tally[False]}  n/a(no response)={hsts_tally[None]}")
    print("WAF vendors detected: " + (", ".join(f"{k}={v}" for k, v in waf_tally.most_common()) or "(none)"))
    print(f"Done. Output: {out_path}")


if __name__ == "__main__":
    main()