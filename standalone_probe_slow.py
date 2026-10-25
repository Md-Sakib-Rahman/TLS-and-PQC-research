#!/usr/bin/env python3
"""
SLOW, sequential HTTP header probe -- for backfilling domains that a faster attempt got
rate-limited/blocked on. Same target and method as standalone_probe.py, but:
  - ONE request at a time (no concurrency at all)
  - a real pause between every request (default 8 seconds)
  - a circuit breaker: if too many requests in a row fail, it stops itself and tells you why,
    instead of grinding through everything uselessly for an hour

WHY THIS EXISTS
  A fast attempt (8 concurrent, no delay) against one shared-hosting server started failing
  100% of requests after about 2 minutes -- consistent with the server's own anti-scraping /
  rate-limiting kicking in. This version is deliberately far gentler: a few requests per
  minute instead of dozens per second, aiming to stay under whatever threshold that server
  is watching for. There is no guarantee this works -- if it still gets blocked quickly, that
  says something real about how sensitive that server's protection is, and the answer is to
  stop trying rather than probe more aggressively.

HOW TO RUN
  Put this file and domains.csv (only the domains still missing) in the same folder, then:
      python3 standalone_probe_slow.py
  It can take a long time for a large list (with the default 8s pause, ~839 domains is
  roughly 2 hours) -- that's expected. Safe to leave running in the background, and safe to
  stop (Ctrl-C) and resume later; it always skips domains already in results.jsonl.

  Optional: change the pause with --delay, e.g.  python3 standalone_probe_slow.py --delay 15
"""

import argparse
import csv
import json
import os
import re
import socket
import ssl
import sys
import time
import warnings
from datetime import datetime, timezone

warnings.filterwarnings("ignore")

USER_AGENT = "bd-tls-pqc-study/1.0 (Md Sakib Rahman, IIUC; contact: sakibrahman.user@gmail.com) [secondary-vantage slow backfill]"
TIMEOUT = 10.0
MAX_HEADER_BYTES = 65536
CIRCUIT_BREAKER_CONSECUTIVE_FAILS = 6   # stop early rather than burn hours on a re-triggered block

HERE = os.path.dirname(os.path.abspath(__file__))
DOMAINS_CSV = os.path.join(HERE, "domains.csv")
OUT_PATH = os.path.join(HERE, "results.jsonl")


def build_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for version in (getattr(ssl.TLSVersion, "SSLv3", None), ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        if version is None:
            continue
        try:
            ctx.minimum_version = version
            break
        except (ValueError, OSError):
            continue
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def parse_response(head_bytes):
    try:
        text = head_bytes.decode("iso-8859-1")
    except Exception:
        return {"status": "parse_error"}
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return {"status": "empty_response"}
    m = re.match(r"HTTP/(\d\.\d)\s+(\d{3})(?:\s+(.*))?", lines[0])
    if not m:
        return {"status": "bad_status_line", "raw": lines[0][:200]}
    headers = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        headers.setdefault(k, []).append(v)
    return {"status": "ok", "http_version": m.group(1), "status_code": int(m.group(2)),
            "reason": (m.group(3) or "")[:200], "headers": {k: "; ".join(v) for k, v in headers.items()}}


def fetch(host, ip, ctx, port=443, timeout=TIMEOUT, max_bytes=MAX_HEADER_BYTES):
    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return {"status": "connect_refused"}
    except (socket.timeout, TimeoutError):
        return {"status": "connect_timeout"}
    except OSError as e:
        return {"status": "connect_error", "error": type(e).__name__}
    sock = raw_sock
    try:
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii", "ignore")
        sock.sendall(req)
        data, deadline, reason = b"", time.monotonic() + timeout, None
        while True:
            if b"\r\n\r\n" in data:
                reason = "complete"
                break
            if len(data) >= max_bytes:
                reason = "too_large"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"status": "timeout"}
            sock.settimeout(remaining)
            chunk = sock.recv(8192)
            if not chunk:
                reason = "closed"
                break
            data += chunk
        if reason == "complete":
            return parse_response(data.split(b"\r\n\r\n", 1)[0])
        if not data:
            return {"status": "empty_response"}
        return {"status": "headers_too_large" if reason == "too_large" else "incomplete_response"}
    except ssl.SSLError as e:
        return {"status": "tls_error", "error": str(e)[:200]}
    except (socket.timeout, TimeoutError):
        return {"status": "timeout"}
    except OSError as e:
        return {"status": "connect_error", "error": f"{type(e).__name__}: {e}"[:200]}
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"[:200]}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--delay", type=float, default=8.0, help="seconds to wait between requests (default 8)")
    args = ap.parse_args()

    if not os.path.exists(DOMAINS_CSV):
        sys.exit(f"ERROR: {DOMAINS_CSV} not found. It must be in the same folder as this script.")
    with open(DOMAINS_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"Loaded {len(rows)} domains from domains.csv")

    done = set()
    if os.path.exists(OUT_PATH):
        with open(OUT_PATH, encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["domain"])
                except Exception:
                    pass
    todo = [r for r in rows if r["domain"] not in done]
    est_minutes = round(len(todo) * (args.delay + 1) / 60, 1)
    print(f"Already done: {len(done)} | To do: {len(todo)}")
    print(f"Delay between requests: {args.delay}s -- estimated time: ~{est_minutes} minutes")
    if not todo:
        print("Nothing to do -- results.jsonl already covers every domain.")
        return

    ctx = build_context()
    ok, consecutive_fail = 0, 0
    with open(OUT_PATH, "a", encoding="utf-8") as out:
        for i, r in enumerate(todo, 1):
            res = fetch(r["domain"], r["ip"], ctx)
            rec = {"domain": r["domain"], "ip": r["ip"],
                   "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **res}
            out.write(json.dumps(rec) + "\n")
            out.flush()
            success = res.get("status") == "ok"
            ok += success
            consecutive_fail = 0 if success else consecutive_fail + 1
            mark = "ok" if success else res["status"]
            print(f"  [{i}/{len(todo)}] {r['domain']:45s} {mark}")
            if consecutive_fail >= CIRCUIT_BREAKER_CONSECUTIVE_FAILS:
                print(f"\nSTOPPING: {consecutive_fail} requests in a row failed.")
                print("This looks like the server is blocking this network too (or is down).")
                print(f"Progress is saved in {OUT_PATH} -- re-running later will resume from here.")
                return
            if i < len(todo):
                time.sleep(args.delay)

    print(f"\nDone. {ok}/{len(todo)} succeeded this run. Wrote {OUT_PATH}")
    print("Please send this file (results.jsonl) back.")


if __name__ == "__main__":
    main()
