#!/usr/bin/env python3
"""
Phase A, step 1: DNS resolution for every domain in the frozen corpus.

Queries per domain: A, AAAA, MX, and (optionally) DS + DNSKEY.
  - A/AAAA  -> does the name resolve to an address (eligible for a 443 check)
  - MX      -> mail hosts, needed later by the SMTP/STARTTLS pass (c4)
  - DS/DNSKEY -> raw DNSSEC records, summarised later by c3
  - AD flag on the A answer -> the validating resolver says the answer was
    DNSSEC-validated (recorded as "ad")

Each query records an explicit status, because "dead" and "unknown" must not be mixed:
  ok | nodata (name exists, no such record) | nxdomain (name does not exist)
  | timeout | servfail (all resolvers failed) | error

If A returns NXDOMAIN the remaining queries are skipped and recorded as nxdomain
(NXDOMAIN applies to the whole name). If A times out or SERVFAILs, AAAA gets ONE attempt
and MX/DS/DNSKEY are recorded as "skipped" (they would hit the same dead nameservers and
each cost up to ~24 s). SERVFAIL is never retried. Worst case per domain is ~32 s, not ~2 min.
Skipped MX/DS/DNSKEY mean "not asked", not "absent" -- a later retry pass can fill them in.

CAVEATS
  - DS/DNSKEY only exist at zone apexes. Most corpus entries are subdomains, so
    DNSSEC rates must be computed at registered-domain level in c3, not over all 22k names.
  - SERVFAIL from a validating resolver can mean a DNSSEC-broken zone, not a dead domain.
    It is kept as its own bucket ("inconclusive"), never counted as dead.

Output (append-only, resumable): data/measurement/runs/<run_id>/raw/dns.jsonl

Usage (from project root):
    python measurement/phase_a_liveness/a1_resolve_dns.py --limit 200     # smoke test first
    python measurement/phase_a_liveness/a1_resolve_dns.py                 # full run
    python measurement/phase_a_liveness/a1_resolve_dns.py --run-id run_2026-09-20   # resume a run
"""

import argparse
import datetime
import os
import platform
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.flags
import dns.resolver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.corpus import latest_frozen, load_corpus, sha256_of
from measurement.common.io_utils import (JsonlWriter, done_keys, load_config, resolve_run_dir,
                                         update_run_meta, utc_now)
from measurement.common.net_utils import RateLimiter

_local = threading.local()


def make_resolver(cfg):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(cfg["nameservers"])
    r.timeout = cfg["timeout_s"]
    r.lifetime = cfg["lifetime_s"]
    r.use_edns(0, dns.flags.DO, 1232)          # DO bit: lets validating resolvers set AD
    return r


def query(resolver, name, rdtype, retries, limiter):
    """One record type, with retries on timeout/SERVFAIL. Always returns a status dict."""
    status = "error"
    for _ in range(retries + 1):
        limiter.wait()
        try:
            ans = resolver.resolve(name, rdtype, raise_on_no_answer=True)
            return {"status": "ok", "values": [r.to_text() for r in ans],
                    "ad": bool(ans.response.flags & dns.flags.AD)}
        except dns.resolver.NXDOMAIN:
            return {"status": "nxdomain"}
        except dns.resolver.NoAnswer:
            return {"status": "nodata"}
        except dns.resolver.NoNameservers:
            return {"status": "servfail"}      # every configured resolver already failed; retrying won't help
        except dns.exception.Timeout:
            status = "timeout"
        except Exception as e:                                  # malformed name, etc.
            return {"status": "error", "detail": type(e).__name__}
    return {"status": status}


def resolve_domain(name, cfg, limiter, resolver_factory=None):
    if not hasattr(_local, "resolver"):
        _local.resolver = (resolver_factory or make_resolver)(cfg)
    res, retries = _local.resolver, cfg["retries"]
    rec = {"domain": name, "ts": utc_now()}
    rec["A"] = query(res, name, "A", retries, limiter)
    if rec["A"]["status"] == "nxdomain":
        for t in ("AAAA", "MX", "DS", "DNSKEY"):
            rec[t] = {"status": "nxdomain"}
    elif rec["A"]["status"] in ("timeout", "servfail", "error"):
        # Nameservers unresponsive or broken: one cheap AAAA attempt (no retries), skip the rest.
        rec["AAAA"] = query(res, name, "AAAA", 0, limiter)
        for t in ("MX", "DS", "DNSKEY"):
            rec[t] = {"status": "skipped"}
    else:
        rec["AAAA"] = query(res, name, "AAAA", retries, limiter)
        rec["MX"] = query(res, name, "MX", retries, limiter)
        if cfg["query_dnssec"]:
            rec["DS"] = query(res, name, "DS", retries, limiter)
            rec["DNSKEY"] = query(res, name, "DNSKEY", retries, limiter)
    rec["resolves"] = rec["A"]["status"] == "ok" or rec.get("AAAA", {}).get("status") == "ok"
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", help="frozen corpus CSV (default: newest in data/measurement/input/)")
    ap.add_argument("--run-id", help="run folder name (default: run_<today>)")
    ap.add_argument("--limit", type=int, help="only the first N domains (smoke test)")
    ap.add_argument("--config", help="alternate config.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    dcfg = cfg["dns"]
    input_path = args.input or latest_frozen()
    rows = load_corpus(input_path)
    domains = [r["domain"] for r in rows][: args.limit]

    run_id = args.run_id or f"run_{datetime.date.today().isoformat()}"
    run_dir = resolve_run_dir(run_id, create=True)
    out_path = os.path.join(run_dir, "raw", "dns.jsonl")

    if not cfg["vantage_point"]:
        print("WARNING: vantage_point is empty in config.yaml -- fill it in before the real run.")

    done = done_keys(out_path)
    todo = [d for d in domains if d not in done]
    print(f"Input: {input_path}\nRun:   {run_id}\nTotal {len(domains)} | already done {len(done)} | to do {len(todo)}")

    update_run_meta(run_dir, "input", {"file": os.path.basename(input_path), "path": input_path,
                                       "sha256": sha256_of(input_path), "rows": len(rows)})
    update_run_meta(run_dir, "environment", {"python": platform.python_version(),
                                             "dnspython": dns.version.version, "os": platform.platform(),
                                             "vantage_point": cfg["vantage_point"]})
    update_run_meta(run_dir, "dns", {"config": dcfg, "started": utc_now()})

    writer, limiter = JsonlWriter(out_path), RateLimiter(dcfg["max_qps"])
    counts = {"resolves": 0, "other": 0}
    try:
        with ThreadPoolExecutor(max_workers=dcfg["workers"]) as pool:
            futures = [pool.submit(resolve_domain, d, dcfg, limiter) for d in todo]
            for i, fut in enumerate(as_completed(futures), 1):
                rec = fut.result()
                writer.write(rec)
                counts["resolves" if rec["resolves"] else "other"] += 1
                if i % 500 == 0 or i == len(todo):
                    print(f"  {i}/{len(todo)}  resolves={counts['resolves']}  not-resolving-or-unknown={counts['other']}")
    except KeyboardInterrupt:
        print("\nInterrupted -- progress is saved; re-run the same command to resume.")
        sys.exit(1)
    finally:
        writer.close()

    update_run_meta(run_dir, "dns", {"config": dcfg, "finished": utc_now(), "scanned_this_session": len(todo)})
    print(f"Done. Output: {out_path}")


if __name__ == "__main__":
    main()