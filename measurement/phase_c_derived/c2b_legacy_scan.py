#!/usr/bin/env python3
"""
Phase C, step 2b: legacy-protocol scan -- SSLv3 acceptance (POODLE) and 3DES acceptance (Sweet32-class).
What the probes mean, why a separate OpenSSL is needed, and how results are classified: legacy_probe.py.

Input:  data/measurement/processed/live_domains.csv for --run-id (verified against that run's
        port443.jsonl, exactly as b1/b2 do).
Output: data/measurement/runs/<run_id>/raw/legacy_sslv3_ip.jsonl   one record per IP (SSLv3 has no SNI)
        data/measurement/runs/<run_id>/raw/legacy_3des.jsonl       one record per domain (3DES, with SNI)
        Both append-only and resumable. Run c2_legacy_cipher_inference.py afterwards to tabulate.

SCHEDULING AND POLITENESS (designed after the rate-limiting of 103.157.135.180 during b2)
  - One worker task per IP: the IP's own connections run strictly one at a time, `per_ip_interval_s`
    apart, so no host ever sees parallel or bursty traffic; different IPs run in parallel
    (`workers`), under a global `max_cps` cap. Largest IPs start first so the long tail is one IP.
  - Circuit breaker: if `breaker_after` consecutive domains on an IP are unreachable (no answer AND a
    plain TCP connect also fails), the IP is abandoned for this run. Nothing is written for those
    domains, so a later re-run retries them: "deferred", never "failed". A domain whose TCP connects
    but whose legacy probe is silent is a protocol-specific drop and is recorded (accepts = None).
  - No application data, identified via the run's meta, low rate. No address rotation or VPN.
  - Progress is printed every `heartbeat_s` (default 20 s). Ctrl-C stops promptly: no new probe is
    started, in-flight probes finish (a few seconds), progress is saved; a second Ctrl-C exits at once.

Pre-flight (aborts on failure): the legacy binary must really support SSLv3 and 3DES, and a local
positive AND negative control must pass (SSLv3/3DES servers accepted, a modern server refused).
--skip-control exists for tests only.

Usage (from project root; build the legacy OpenSSL first: bash tools/build_legacy_openssl.sh):
    python measurement/phase_c_derived/c2b_legacy_scan.py --run-id run_2026-09-19 --limit 100   # smoke
    python measurement/phase_c_derived/c2b_legacy_scan.py --run-id run_2026-09-19               # full
"""

import argparse
import os
import random
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import (BASE, PROCESSED_DIR, JsonlWriter, done_keys, load_config, read_jsonl,
                                         resolve_run_dir, update_run_meta, utc_now)
from measurement.common.net_utils import RateLimiter
from measurement.phase_b_tls.b1_tls_handshake_scan import load_live, sha256_file
from measurement.phase_c_derived import legacy_probe

PORT = 443


def process_ip(ip, domains, need_sslv3, *, openssl, port, timeout, interval, breaker_after, pace,
               write_sslv3, write_des3, probe_sslv3=legacy_probe.probe_sslv3, probe_3des=legacy_probe.probe_3des,
               tcp_ok=legacy_probe.tcp_reachable, sleep=time.sleep, should_stop=lambda: False):
    """
    Everything for one IP, sequentially. Returns {"ip", "tripped", "deferred"}: `deferred` are domains
    (and, if flagged, the SSLv3 probe) that got no usable answer and were NOT written, so a re-run
    retries them. If `should_stop()` turns true (Ctrl-C) the IP is left as it is: untried domains are
    simply still pending, not "deferred". The probe functions, `sleep` and `should_stop` are injectable
    so this logic is unit-testable without a network.
    """
    state = {"first": True}

    def stopped(deferred=(), tripped=False):
        return {"ip": ip, "tripped": tripped, "deferred": list(deferred), "sslv3_deferred": False, "stopped": True}

    def spacing():
        if not state["first"]:
            sleep(interval)
        state["first"] = False

    if need_sslv3:
        spacing()
        if should_stop():
            return stopped()
        r = probe_sslv3(openssl, ip, port, timeout, pace=pace)
        if r["accepts_sslv3"] is None and not tcp_ok(ip, port):
            return {"ip": ip, "tripped": True, "deferred": list(domains), "sslv3_deferred": True}
        write_sslv3({"ip": ip, "ts": utc_now(), **r})

    deferred, consecutive, tripped = [], 0, False
    for i, d in enumerate(domains):
        spacing()
        if should_stop():
            return stopped(deferred)
        r = probe_3des(openssl, d, ip, port, timeout, pace=pace)
        unreachable = (r["accepts_3des"] is None and r["status"] in ("timeout", "connect_failed")
                       and not tcp_ok(ip, port))
        if unreachable:
            deferred.append(d)
            consecutive += 1
            if consecutive >= breaker_after:
                deferred.extend(domains[i + 1:])
                tripped = True
                break
            continue
        consecutive = 0
        write_des3({"domain": d, "ip": ip, "ts": utc_now(), **r})
    return {"ip": ip, "tripped": tripped, "deferred": deferred, "sslv3_deferred": False}


def tally(sslv3_path, des3_path, live_by_domain):
    ips = {r["ip"]: r for r in read_jsonl(sslv3_path)}
    doms = {r["domain"]: r for r in read_jsonl(des3_path)}
    wanted_ips = {v["ip"] for v in live_by_domain.values()}
    ip_status = Counter(r["offer_all"]["status"] for ip, r in ips.items() if ip in wanted_ips)
    poodle_ips = sum(1 for ip, r in ips.items() if ip in wanted_ips and r.get("poodle_exposed") is True)
    sslv3_ips = sum(1 for ip, r in ips.items() if ip in wanted_ips and r.get("accepts_sslv3") is True)
    dom_sslv3 = sum(1 for d, v in live_by_domain.items() if ips.get(v["ip"], {}).get("accepts_sslv3") is True)
    dom_poodle = sum(1 for d, v in live_by_domain.items() if ips.get(v["ip"], {}).get("poodle_exposed") is True)
    des_status = Counter(r["status"] for d, r in doms.items() if d in live_by_domain)
    des_yes = sum(1 for d, r in doms.items() if d in live_by_domain and r.get("accepts_3des") is True)
    return {"ips_probed": sum(ip_status.values()), "ip_status": dict(ip_status), "sslv3_ips": sslv3_ips,
            "poodle_ips": poodle_ips, "domains_on_sslv3_ips": dom_sslv3, "domains_on_poodle_ips": dom_poodle,
            "domains_3des_probed": sum(des_status.values()), "des_status": dict(des_status), "des_yes": des_yes}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--limit", type=int, help="only N domains (smoke test; random but fixed sample)")
    ap.add_argument("--config", help="alternate config.yaml")
    ap.add_argument("--openssl", help="path to the legacy openssl binary (default: config legacy.openssl_path)")
    ap.add_argument("--timeout-s", type=float, help="override legacy.timeout_s")
    ap.add_argument("--per-ip-interval-s", type=float, help="override legacy.per_ip_interval_s")
    ap.add_argument("--skip-control", action="store_true", help="skip the local positive/negative control (tests only)")
    args = ap.parse_args()

    cfg = dict(load_config(args.config)["legacy"])
    if args.timeout_s is not None:
        cfg["timeout_s"] = args.timeout_s
    if args.per_ip_interval_s is not None:
        cfg["per_ip_interval_s"] = args.per_ip_interval_s
    openssl = args.openssl or cfg["openssl_path"]
    if not os.path.isabs(openssl):
        openssl = os.path.join(BASE, openssl)

    try:
        version = legacy_probe.check_capabilities(openssl)
    except RuntimeError as e:
        sys.exit(f"ERROR: {e}")
    control = "skipped"
    if not args.skip_control:
        try:
            control = legacy_probe.self_test(openssl)
        except RuntimeError as e:
            sys.exit(f"ERROR: {e}")
        print("Control check passed (local SSLv3/3DES servers accepted, modern server refused).")

    run_dir = resolve_run_dir(args.run_id)
    live_path = os.path.join(PROCESSED_DIR, "live_domains.csv")
    live = load_live(run_dir, live_path)
    if args.limit:
        live = random.Random(7).sample(live, min(args.limit, len(live)))
    live_by_domain = {r["domain"]: r for r in live}
    sslv3_path = os.path.join(run_dir, "raw", "legacy_sslv3_ip.jsonl")
    des3_path = os.path.join(run_dir, "raw", "legacy_3des.jsonl")

    groups = defaultdict(list)
    for r in live:
        groups[r["ip"]].append(r["domain"])
    done_ips, done_doms = done_keys(sslv3_path, "ip"), done_keys(des3_path, "domain")
    tasks = []
    for ip, doms in groups.items():
        todo = [d for d in doms if d not in done_doms]
        need = ip not in done_ips
        if need or todo:
            tasks.append((ip, todo, need))
    tasks.sort(key=lambda t: -len(t[1]))                     # longest first: the tail is one big IP
    print(f"Run: {os.path.basename(run_dir)}\nLegacy OpenSSL: {version}\nLive domains {len(live)} on {len(groups)} IPs | "
          f"IPs still needing SSLv3: {sum(1 for t in tasks if t[2])} | domains still needing 3DES: {sum(len(t[1]) for t in tasks)}")

    meta = {"config": cfg, "started": utc_now(), "openssl": version, "openssl_path": openssl,
            "openssl_sha256": sha256_file(openssl), "control": control,
            "cipher_strings": {"sslv3_all": legacy_probe.SSLV3_ALL, "sslv3_cbc_only": legacy_probe.SSLV3_CBC_ONLY,
                               "3des": legacy_probe.DES3},
            "input": {"file": live_path, "sha256": sha256_file(live_path)}}
    update_run_meta(run_dir, "legacy", meta)

    if tasks:
        biggest = max(len(t[1]) for t in tasks)
        print(f"Largest IP has {biggest} domains: at least ~{biggest * (cfg['per_ip_interval_s'] + 0.5) / 60:.0f} min "
              f"(one connection at a time per IP, {cfg['per_ip_interval_s']} s apart). Progress prints every "
              f"{cfg.get('heartbeat_s', 20)} s; Ctrl-C stops promptly and the run resumes where it left off.", flush=True)

    limiter = RateLimiter(cfg["max_cps"])
    w_ssl, w_des = JsonlWriter(sslv3_path), JsonlWriter(des3_path)
    lock, counters = threading.Lock(), {"domains": 0, "ips": 0, "deferred": 0}
    tripped, stop, finished = [], threading.Event(), threading.Event()
    total_ips, total_domains, t0 = len(tasks), sum(len(t[1]) for t in tasks), time.monotonic()

    def write_des(rec):
        w_des.write(rec)
        with lock:
            counters["domains"] += 1

    def heartbeat():
        while not finished.wait(cfg.get("heartbeat_s", 20)):
            with lock:
                d, i, df = counters["domains"], counters["ips"], counters["deferred"]
            e = int(time.monotonic() - t0)
            print(f"  [{e // 60}m{e % 60:02d}s] IPs finished {i}/{total_ips} | 3DES domains {d}/{total_domains}"
                  + (f" | deferred {df}" if df else ""), flush=True)

    threading.Thread(target=heartbeat, daemon=True).start()
    pool, interrupted = ThreadPoolExecutor(max_workers=cfg["workers"]), False
    try:
        futures = [pool.submit(process_ip, ip, todo, need, openssl=openssl, port=PORT, timeout=cfg["timeout_s"],
                               interval=cfg["per_ip_interval_s"], breaker_after=cfg["breaker_after"],
                               pace=limiter.wait, write_sslv3=w_ssl.write, write_des3=write_des,
                               sleep=stop.wait, should_stop=stop.is_set)
                   for ip, todo, need in tasks]
        for fut in as_completed(futures):
            res = fut.result()
            with lock:
                counters["ips"] += 1
                counters["deferred"] += len(res["deferred"])
                if res["tripped"]:
                    tripped.append(res["ip"])
    except KeyboardInterrupt:
        interrupted = True
        stop.set()
        print("\nStopping: no new probes are started; in-flight ones finish (a few seconds). Progress is saved. "
              "Press Ctrl-C again to exit at once.", flush=True)
        pool.shutdown(wait=False, cancel_futures=True)
        try:
            pool.shutdown(wait=True)
        except KeyboardInterrupt:
            os._exit(1)            # every record is flushed line by line, so nothing is lost
    finally:
        finished.set()
        stop.set()
        pool.shutdown(wait=True)
        w_ssl.close()
        w_des.close()

    deferred_total = [counters["deferred"]]
    t = tally(sslv3_path, des3_path, live_by_domain)
    update_run_meta(run_dir, "legacy", {**meta, "finished": utc_now(), "tripped_ips": tripped,
                                        "deferred_domains": deferred_total[0], "interrupted": interrupted})
    print(f"SSLv3 (per IP): {t['ips_probed']} IPs probed {t['ip_status']} | accepting SSLv3: {t['sslv3_ips']} | "
          f"POODLE-exposed: {t['poodle_ips']}  (covering {t['domains_on_sslv3_ips']} / {t['domains_on_poodle_ips']} domains)")
    print(f"3DES (per domain): {t['domains_3des_probed']} probed {t['des_status']} | accept 3DES when offered: {t['des_yes']}")
    if tripped or deferred_total[0]:
        print(f"DEFERRED: {deferred_total[0]} domains on {len(tripped)} unreachable IPs were not recorded "
              f"(circuit breaker). Re-run later to retry them. IPs: {tripped[:10]}")
    if interrupted:
        print("Interrupted -- progress is saved; re-run the same command to resume.")
        sys.exit(1)
    print(f"Done. Output: {sslv3_path} and {des3_path}")


if __name__ == "__main__":
    main()