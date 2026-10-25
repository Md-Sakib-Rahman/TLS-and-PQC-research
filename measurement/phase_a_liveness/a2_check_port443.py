#!/usr/bin/env python3
"""
Phase A, step 2: is TCP port 443 reachable?

Reads the addresses found by a1 (does NOT re-resolve, so results stay consistent
with the DNS snapshot). For each resolving domain, tries up to `max_ips_tried`
addresses (IPv4 first) with a plain TCP connect, then closes immediately.
No TLS handshake and no data is sent here -- that is Phase B.

Domain-level result:
  open         a TCP connection succeeded
  closed       every attempt was actively refused (RST)
  no_response  timeouts / unreachable / other errors, and nothing open

CAVEATS
  - "open" only means something accepted the TCP connection, not that it speaks TLS.
  - If the scanning machine has no IPv6 connectivity, IPv6-only domains will show
    no_response. Each attempt's family and error are kept so this can be checked.
  - CONTROL CHECK: before scanning, a2 tries port 443 on two reserved, never-assigned
    addresses (TEST-NET-1/3). If either "opens", the network is answering TCP handshakes
    on behalf of unreachable hosts (transparent proxy, captive portal, filtering ISP) and
    every "open" result would be meaningless -- so a2 aborts. Use --skip-control to bypass.
  - ONE CONNECTION PER UNIQUE IP. Whether a TCP port accepts connections is a property of
    the address, not of the hostname, and thousands of corpus domains share hosting (one IP
    can serve 1,000+ domains). Each IP is probed once and the result is reused for every
    domain that resolves to it. This is equivalent for a TCP-level check, ~4x fewer
    connections, and far gentler on both the servers and the scanning network. The
    config key max_per_ip is therefore obsolete and ignored.
    Consequence: domains sharing an IP share one outcome -- they are not independent.

Output (append-only, resumable): data/measurement/runs/<run_id>/raw/port443.jsonl

Usage: python measurement/phase_a_liveness/a2_check_port443.py [--run-id ID] [--limit N]
"""

import argparse
import errno
import os
import random
import socket
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import (JsonlWriter, done_keys, load_config, read_jsonl,
                                         resolve_run_dir, update_run_meta, utc_now)
from measurement.common.net_utils import RateLimiter

class ProbeCache:
    """Thread-safe: each (ip, port) is connected to at most once; later callers reuse the result."""

    def __init__(self):
        self._results, self._locks, self._guard = {}, {}, threading.Lock()

    def probe(self, ip, family, port, timeout, limiter):
        key = (ip, port)
        with self._guard:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:                                   # concurrent callers for the same IP wait here
            if key not in self._results:
                limiter.wait()
                self._results[key] = try_connect(ip, family, port, timeout)
            return self._results[key]


CONTROL_IPS = ["192.0.2.1", "203.0.113.5"]      # TEST-NET-1 / TEST-NET-3: reserved, never assigned


def control_check(timeout):
    """Returns (results_by_ip, ok). ok is False if any unassigned address 'accepts' a connection."""
    results = {ip: try_connect(ip, 4, 443, timeout)[0] for ip in CONTROL_IPS}
    return results, not any(r == "open" for r in results.values())


def candidate_ips(dns_rec, cfg):
    """IPv4 first, then IPv6 (if enabled); capped at max_ips_tried."""
    ips = [(v.strip(), 4) for v in dns_rec.get("A", {}).get("values", [])]
    if cfg["try_ipv6"]:
        ips += [(v.strip(), 6) for v in dns_rec.get("AAAA", {}).get("values", [])]
    return ips[: cfg["max_ips_tried"]]


def try_connect(ip, family, port, timeout):
    """Returns (result, connect_ms). result: open | refused | timeout | unreachable | error:<name>"""
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.monotonic()
    try:
        s.connect((ip, port))
        return "open", round((time.monotonic() - t0) * 1000)
    except ConnectionRefusedError:
        return "refused", None
    except (socket.timeout, TimeoutError):
        return "timeout", None
    except OSError as e:
        if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            return "unreachable", None
        return f"error:{errno.errorcode.get(e.errno, 'unknown')}", None
    finally:
        s.close()


def check_domain(dns_rec, cfg, limiter, port=443, cache=None):
    cache = cache or ProbeCache()                    # no shared cache -> nothing is reused
    attempts, status, open_ip, open_family = [], "no_response", None, None
    for ip, family in candidate_ips(dns_rec, cfg):
        result, ms = cache.probe(ip, family, port, cfg["connect_timeout_s"], limiter)
        attempts.append({"ip": ip, "family": family, "result": result, "ms": ms})
        if result == "open":
            status, open_ip, open_family = "open", ip, family
            break
    if status != "open" and attempts and all(a["result"] == "refused" for a in attempts):
        status = "closed"
    return {"domain": dns_rec["domain"], "ts": utc_now(), "port443": status,
            "ip": open_ip, "family": open_family, "attempts": attempts}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", help="run folder (default: newest)")
    ap.add_argument("--limit", type=int, help="only the first N resolving domains (smoke test)")
    ap.add_argument("--config", help="alternate config.yaml")
    ap.add_argument("--skip-control", action="store_true", help="skip the unassigned-address control check (tests only)")
    args = ap.parse_args()

    cfg = load_config(args.config)["port443"]
    run_dir = resolve_run_dir(args.run_id)
    dns_path = os.path.join(run_dir, "raw", "dns.jsonl")
    out_path = os.path.join(run_dir, "raw", "port443.jsonl")

    resolving = [r for r in read_jsonl(dns_path) if r.get("resolves")]
    if not resolving:
        sys.exit(f"ERROR: no resolving domains found in {dns_path}. Run a1 first.")
    random.Random(42).shuffle(resolving)
    resolving = resolving[: args.limit]

    done = done_keys(out_path)
    todo = [r for r in resolving if r["domain"] not in done]
    print(f"Run: {os.path.basename(run_dir)}\nResolving domains {len(resolving)} | already done {len(done)} | to do {len(todo)}")
    meta = {"config": cfg, "started": utc_now(), "control": "skipped", "method": "one TCP connect per unique IP"}
    if todo and not args.skip_control:
        results, ok = control_check(cfg["connect_timeout_s"])
        meta["control"] = results
        if not ok:
            update_run_meta(run_dir, "port443", meta)
            sys.exit(f"ERROR: control check failed -- unassigned addresses accepted a connection: {results}\n"
                     "This network answers TCP handshakes for hosts that cannot exist (proxy / captive portal / "
                     "filtering), so 'open' results would be unreliable. Try another network.")
        print(f"Control check passed (unassigned addresses did not accept connections): {results}")
    update_run_meta(run_dir, "port443", meta)

    writer, limiter, cache = JsonlWriter(out_path), RateLimiter(cfg["max_cps"]), ProbeCache()
    tally = defaultdict(int)
    try:
        with ThreadPoolExecutor(max_workers=cfg["workers"]) as pool:
            futures = [pool.submit(check_domain, r, cfg, limiter, cache=cache) for r in todo]
            for i, fut in enumerate(as_completed(futures), 1):
                rec = fut.result()
                writer.write(rec)
                tally[rec["port443"]] += 1
                if i % 500 == 0 or i == len(todo):
                    print(f"  {i}/{len(todo)}  " + "  ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    except KeyboardInterrupt:
        print("\nInterrupted -- progress is saved; re-run the same command to resume.")
        sys.exit(1)
    finally:
        writer.close()

    update_run_meta(run_dir, "port443", {**meta, "finished": utc_now(), "scanned_this_session": len(todo)})
    print(f"Done. Output: {out_path}")


if __name__ == "__main__":
    main()