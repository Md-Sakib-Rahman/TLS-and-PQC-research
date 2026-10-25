#!/usr/bin/env python3
"""
Phase C, step 4: SMTP/STARTTLS scan. The only new active scan in Phase C -- see smtp_probe.py for
exactly what is sent (banner, EHLO, STARTTLS, TLS handshake, QUIT; no email is ever composed or sent).

SCOPE: every domain with a usable MX record, independent of Phase A/B web liveness
  A domain can run mail with no live website at all (Phase A found 816 such domains; 118 of them
  have an MX record -- PLAN.md Section 5.4/5.5). This step is therefore scoped from
  data/measurement/runs/<run_id>/raw/dns.jsonl directly (every domain whose MX query succeeded with
  a non-null target), NOT from live_domains.csv or phase_b_domains.csv, which would silently drop
  those mail-only domains. Category/tier come from liveness_all.csv, which covers the full corpus.

ONE PROBE PER MAIL SERVER, NOT PER DOMAIN
  STARTTLS support is a property of the mail SERVER, the same reasoning c2b used for SSLv3 (which
  has no SNI). Here the reason is different: SMTP's EHLO/STARTTLS exchange is not host-specific the
  way an HTTPS request is -- a domain's "lowest preference" (RFC 5321 5.1) MX host is probed once;
  every domain sharing that host gets that one result. Many domains share one provider's MX host
  (Google's aspmx.l.google.com, or a single government mail relay such as bcc.gov.bd's lbmx host --
  seen directly in this corpus), so this avoids hundreds of redundant connections to one server, the
  same concern that caused the b2 rate-limiting incident.

MX HOSTNAME RESOLUTION
  Resolved with dnspython against the SAME explicit resolvers as a1 (config.dns.nameservers), for
  the same reproducibility reason -- not the OS resolver, which could silently vary by machine.

POLITENESS
  The shared Gate (measurement/common/net_utils.py) caps simultaneous connections per RESOLVED IP
  (several hostnames, e.g. several government relays, can share one real server) and paces them.

PRE-FLIGHT CONTROL CHECK (aborts the run if it fails; --skip-control for tests only)
  Outbound port 25 is commonly blocked by residential/cloud ISPs. Before scanning, this probes a
  known STARTTLS-supporting public mail server (smtp.gmail.com) and ABORTS if it does not succeed
  with STARTTLS offered -- this replaces relying on a one-off manual `nc` check, which could be
  stale by the time the real run happens.

SAFETY NET AGAINST A MID-RUN BLOCK
  The control check only proves port 25 worked at the START. If --abort-after-n-failures consecutive
  hosts all fail to even connect partway through a long run, the run stops itself (clearly) rather
  than grinding through hundreds more guaranteed failures. This does not apply to hosts that connect
  but answer badly (smtp_error, no_starttls, etc.) -- only to connect-level failure, which is the
  specific signature of a port being newly blocked.

  FIX (2026-10-15): a bare "timeout" status can only happen AFTER the TCP connect already succeeded
  (the connect-level timeout is its own distinct status, "connect_timeout" -- see smtp_probe.py).
  Treating every "timeout" as connect-level evidence was wrong: a host that got through banner+EHLO
  and even had STARTTLS accepted, then merely stalled during the TLS handshake, is proof the port is
  OPEN, not blocked -- counting it toward this abort risked a false "port 25 may have become blocked"
  abort during a run that was actually fine. Only a timeout at the "banner" or "ehlo" stage (nothing
  was ever heard back at all) is treated as connect-level; "starttls"/"tls_handshake"-stage timeouts
  are not, since reaching those stages already proves the host was reachable and responsive.

Outputs:
  data/measurement/runs/<run_id>/raw/smtp_hosts.jsonl   one row per unique MX host (resumable)
  data/measurement/processed/phase_c4_domains.csv        one row per domain, joined to its MX host's result
  results/tables/phase_c4_by_category.csv, _by_tier.csv  per-domain AND per-server(=per-host) views
  results/tables/phase_c4_report.md

Usage (from project root):
    python measurement/phase_c_derived/c4_smtp_scan.py --run-id run_2026-09-19 --limit 50   # smoke
    python measurement/phase_c_derived/c4_smtp_scan.py --run-id run_2026-09-19               # full
"""

import argparse
import csv
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
from measurement.common.net_utils import Gate
from measurement.phase_b_tls.b3_parse_results import OUT_TABLES, pct, server_weighted, write_csv
from measurement.phase_c_derived import smtp_probe as S

UA_PLACEHOLDER_MARKER = "FILL-IN"


def extract_primary_mx(dns_path):
    """{domain: mx_host} for every domain whose MX query succeeded with a usable (non-null) target."""
    out = {}
    for r in read_jsonl(dns_path):
        mx = r.get("MX") or {}
        if mx.get("status") != "ok" or not mx.get("values"):
            continue
        try:
            best = min(mx["values"], key=lambda v: int(v.split()[0]))
        except (ValueError, IndexError):
            continue
        parts = best.split()
        if len(parts) < 2:
            continue
        host = parts[1].rstrip(".").lower()
        if host:                                           # a null MX ("0 .") rstrips to "" -- correctly skipped
            out[r["domain"]] = host
    return out


def resolve_hosts(hosts, nameservers, timeout_s):
    """{mx_host: ip or None}, using dnspython against the configured explicit resolvers."""
    import dns.exception
    import dns.resolver
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(nameservers) or ["1.1.1.1", "8.8.8.8"]
    resolver.timeout, resolver.lifetime = timeout_s, timeout_s * 2
    out = {}
    for h in hosts:
        try:
            ans = resolver.resolve(h, "A", raise_on_no_answer=True)
            out[h] = ans[0].to_text()
        except (dns.exception.DNSException, Exception):
            out[h] = None
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--limit", type=int, help="only N mail hosts (smoke test; random but fixed sample)")
    ap.add_argument("--config", help="alternate config.yaml")
    ap.add_argument("--skip-control", action="store_true", help="skip the pre-flight control check (tests only)")
    ap.add_argument("--skip-ehlo-check", action="store_true", help="allow the placeholder EHLO name (tests only)")
    ap.add_argument("--abort-after-n-failures", type=int, default=40,
                    help="consecutive connect-level failures across DIFFERENT hosts before aborting (default 40)")
    args = ap.parse_args()

    cfg = dict(load_config(args.config)["smtp"])
    if not args.skip_ehlo_check and UA_PLACEHOLDER_MARKER in cfg["ehlo_name"]:
        sys.exit("ERROR: measurement/config.yaml's smtp.ehlo_name is still the placeholder.\n"
                 "This name is announced to every mail server probed -- set it to a real, resolvable "
                 "hostname that identifies the study (never a bare IP) before scanning the live corpus.")

    run_dir = resolve_run_dir(args.run_id)
    dns_path = os.path.join(run_dir, "raw", "dns.jsonl")
    out_path = os.path.join(run_dir, "raw", "smtp_hosts.jsonl")
    dns_cfg = load_config(args.config)["dns"]

    domain_to_host = extract_primary_mx(dns_path)
    hosts = sorted(set(domain_to_host.values()))
    if args.limit:
        hosts = random.Random(7).sample(hosts, min(args.limit, len(hosts)))
        domain_to_host = {d: h for d, h in domain_to_host.items() if h in set(hosts)}
    by_host = defaultdict(list)
    for d, h in domain_to_host.items():
        by_host[h].append(d)

    ctx = S.build_context()
    control = "skipped"
    if not args.skip_control:
        result, ok = S.control_check(cfg["control_host"], cfg["port"], cfg["ehlo_name"], cfg["timeout_s"])
        control = result
        if not ok:
            sys.exit(f"ERROR: positive control failed against {cfg['control_host']}: {result}\n"
                     f"Possible causes: outbound port {cfg['port']} is blocked by this network, or the "
                     f"control host no longer offers STARTTLS. Do not scan until resolved.")
        print(f"Control check passed ({cfg['control_host']}: STARTTLS offered, TLS {result.get('tls_version')}).")

    done = done_keys(out_path, "mx_host")
    todo = sorted(h for h in hosts if h not in done)
    print(f"Run: {os.path.basename(run_dir)}\nEHLO name: {cfg['ehlo_name']}\n"
          f"Domains with usable MX: {len(domain_to_host)} | unique MX hosts: {len(hosts)} | "
          f"already done: {len(done)} | to do: {len(todo)}")
    if not todo:
        print("Nothing to scan.")
    else:
        print(f"Resolving {len(todo)} MX hostnames via {dns_cfg['nameservers']}...")
        ips = resolve_hosts(todo, dns_cfg["nameservers"], dns_cfg["timeout_s"])
        n_resolved = sum(1 for v in ips.values() if v)
        print(f"Resolved {n_resolved}/{len(todo)}.")

        meta = {"config": cfg, "started": utc_now(), "control": control,
                "input": {"file": dns_path}, "resolvers": dns_cfg["nameservers"]}
        update_run_meta(run_dir, "smtp", meta)

        gate = Gate(cfg["max_per_ip"], cfg["max_cps"])
        writer = JsonlWriter(out_path)
        lock = threading.Lock()
        counters = {"done": 0, "consecutive_connect_fail": 0}
        aborted = threading.Event()

        # 2026-10-15 FIX: see module docstring "SAFETY NET AGAINST A MID-RUN BLOCK". A bare "timeout"
        # can only happen after the TCP connect already succeeded (connect_timeout is the distinct
        # status for a connect-level timeout), so it is only treated as connect-level evidence when it
        # happened before any protocol reply was ever received at all (banner/ehlo stage). A timeout
        # at "starttls" or "tls_handshake" proves the host WAS reachable and responsive and must not
        # count toward "port 25 may have become blocked".
        CONNECT_FAIL = {"connect_refused", "connect_timeout", "connect_failed"}
        EARLY_TIMEOUT_STAGES = {"banner", "ehlo"}

        def is_connect_level_fail(rec):
            if rec["status"] in CONNECT_FAIL:
                return True
            return rec["status"] == "timeout" and rec.get("stage") in EARLY_TIMEOUT_STAGES

        def scan_one(host):
            if aborted.is_set():
                return None
            ip = ips.get(host)
            if not ip:
                rec = {"mx_host": host, "status": "resolve_failed"}
            else:
                with gate(ip):
                    rec = S.probe_smtp(host, ip, cfg["ehlo_name"], cfg["port"], cfg["timeout_s"], ctx)
            rec["ts"] = utc_now()
            writer.write(rec)
            with lock:
                counters["done"] += 1
                if is_connect_level_fail(rec):
                    counters["consecutive_connect_fail"] += 1
                    if counters["consecutive_connect_fail"] >= args.abort_after_n_failures:
                        aborted.set()
                else:
                    counters["consecutive_connect_fail"] = 0
                if counters["done"] % 50 == 0:
                    print(f"  {counters['done']}/{len(todo)} hosts probed")
            return rec

        try:
            with ThreadPoolExecutor(max_workers=cfg["workers"]) as pool:
                futures = [pool.submit(scan_one, h) for h in todo]
                for fut in as_completed(futures):
                    fut.result()
        except KeyboardInterrupt:
            print("\nInterrupted -- progress is saved; re-run the same command to resume.")
            writer.close()
            sys.exit(1)
        finally:
            writer.close()

        update_run_meta(run_dir, "smtp", {**meta, "finished": utc_now(), "aborted": aborted.is_set()})
        if aborted.is_set():
            print(f"\nABORTED: {args.abort_after_n_failures} consecutive hosts failed to connect. "
                  f"Outbound port {cfg['port']} may have become blocked mid-run. "
                  f"{counters['done']}/{len(todo)} hosts were attempted before stopping; re-run to resume "
                  f"once connectivity is confirmed (e.g. `nc -zv {cfg['control_host']} {cfg['port']}`).")
            sys.exit(1)

    build_report(run_dir, dns_path, domain_to_host, by_host)


def build_report(run_dir, dns_path, domain_to_host, by_host):
    liveness_path = os.path.join(PROCESSED_DIR, "liveness_all.csv")
    if not os.path.exists(liveness_path):
        sys.exit(f"ERROR: {liveness_path} not found -- run a3_build_live_list.py first.")
    with open(liveness_path, newline="", encoding="utf-8") as f:
        meta_by_domain = {r["domain"]: r for r in csv.DictReader(f)}

    results = {r["mx_host"]: r for r in read_jsonl(os.path.join(run_dir, "raw", "smtp_hosts.jsonl"))}
    rows = []
    for d, host in domain_to_host.items():
        info = meta_by_domain.get(d, {"category": "unknown", "tier": "unknown"})
        r = results.get(host)
        rows.append({
            "domain": d, "category": info.get("category", "unknown"), "tier": info.get("tier", "unknown"),
            "mx_host": host, "status": r["status"] if r else "not_scanned",
            "starttls_offered": r.get("starttls_offered") if r else None,
            "tls_version": r.get("tls_version") if r else None, "cipher": r.get("cipher") if r else None,
            "group": r.get("group") if r else None,  # 2026-10-15: raw PQ key-exchange group, see
        })                                            # smtp_probe.py's patched build_context()

    # 2026-10-15 FIX (PLAN.md Section 4.14 / Standing Rule 9 -- "inconclusive != dead"):
    # the STARTTLS-offered rate's denominator must only count domains where we actually learned
    # whether STARTTLS is offered. The previous version used `r["status"] != "not_scanned"`, which
    # counted every unreachable status (connect_timeout, timeout, resolve_failed, connect_refused,
    # closed, smtp_error) as if it were conclusive -- that is what made the self-reported rate
    # 1997/2633 = 75.8% instead of the correct 1997/2001 = 99.8% on the original pre-group-capture
    # run (see PLAN.md for both numbers).
    #
    # A first fix attempt whitelisted specific status strings ({"ok", "no_starttls"}), but the
    # 2026-10-15 SMTP PQ-group-capture patch to smtp_probe.py introduced a further status,
    # "starttls_rejected" (EHLO advertises STARTTLS, i.e. starttls_offered IS known to be True, but
    # the actual STARTTLS command/negotiation then fails) -- a status-string whitelist silently
    # dropped those confirmed-True rows from both sides of the fraction, undercounting. Testing the
    # `starttls_offered` field itself instead of enumerating status strings is immune to any further
    # status value smtp_probe.py might add later, and is already the pattern tls_handshake_ok's own
    # denominator below uses.
    def conclusive_for_starttls(r):
        return r["starttls_offered"] is not None

    def offered(r):
        return r["starttls_offered"] is True

    def succeeded(r):
        return r["status"] == "ok"

    METRICS = [("starttls_offered", conclusive_for_starttls, offered),
               ("tls_handshake_ok", lambda r: r["starttls_offered"] is True, succeeded)]

    def group_ip(r):
        return r["mx_host"]                                         # "server" here = the MX host, see module docstring

    def summarize(name, rs):
        out = {"group": name, "domains": len(rs), "mx_hosts": len({group_ip(r) for r in rs})}
        for m, den, num in METRICS:
            d = [r for r in rs if den(r)]
            n = sum(1 for r in d if num(r))
            out[f"{m}_n"], out[f"{m}_den"] = n, len(d)
            out[f"{m}_dom_pct"] = pct(n, len(d))
            srv_rows = [dict(r, ip=group_ip(r)) for r in rs]
            out[f"{m}_srv_pct"], out[f"{m}_srv_den"] = server_weighted(
                srv_rows, lambda r, den=den: den(r), lambda r, num=num: num(r))
        return out

    def table(key):
        groups = defaultdict(list)
        for r in rows:
            groups[r[key]].append(r)
        t = [summarize(g, rs) for g, rs in sorted(groups.items(), key=lambda kv: -len(kv[1]))]
        t.append(summarize("ALL", rows))
        return t

    by_cat, by_tier = table("category"), table("tier")
    os.makedirs(OUT_TABLES, exist_ok=True)
    write_csv(os.path.join(PROCESSED_DIR, "phase_c4_domains.csv"), rows,
              ["domain", "category", "tier", "mx_host", "status", "starttls_offered", "tls_version",
               "cipher", "group"])
    write_csv(os.path.join(OUT_TABLES, "phase_c4_by_category.csv"), by_cat)
    write_csv(os.path.join(OUT_TABLES, "phase_c4_by_tier.csv"), by_tier)

    a = by_cat[-1]
    status_count = Counter(r["status"] for r in rows)
    top_hosts = sorted(by_host.items(), key=lambda kv: -len(kv[1]))[:10]
    labels = ["starttls_offered", "tls_handshake_ok"]
    label_text = {"starttls_offered": "STARTTLS offered", "tls_handshake_ok": "TLS handshake completed (of offered)"}

    def cell(r, m):
        n, den = r[m + "_n"], r[m + "_den"]
        if den == 0:
            return "– (no conclusive result)"
        dom, srv = r[m + "_dom_pct"], r[m + "_srv_pct"]
        srv_text = f"{srv}%" if srv is not None else "–"
        return f"{n}/{den} ({dom}% / {srv_text})"

    def md_table(t):
        head = ["group", "domains", "mx hosts"] + [label_text[m] for m in labels]
        lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        for r in t:
            lines.append("| " + " | ".join([r["group"], str(r["domains"]), str(r["mx_hosts"])] +
                        [cell(r, m) for m in labels]) + " |")
        return "\n".join(lines)

    md = "\n".join([
        f"# Phase C4: SMTP/STARTTLS ({os.path.basename(run_dir)})", "",
        f"- {len(domain_to_host)} domains have a usable MX record (independent of HTTPS liveness), on {len(by_host)} "
        f"unique mail servers. Cells: n/den (per-domain % / per-server %).",
        "- Scope note: this set includes mail-only domains (no live website) that b1/b2/b3 never scanned.",
        "- No email is composed or sent: banner + EHLO + STARTTLS + TLS handshake + QUIT only.",
        "- A server's reverse-DNS (PTR) check against our connecting IP is outside this tool's control; a rejection "
        "for that reason looks like `smtp_error` and is a stated limitation, not necessarily a missing feature.",
        "- **STARTTLS-offered denominator (fixed 2026-10-15):** only domains where `starttls_offered` is "
        "not None count -- i.e. EHLO was actually read, whatever happened afterward (this includes "
        "`starttls_rejected` domains, where STARTTLS was confirmed advertised but the subsequent negotiation "
        "failed). Every connection-level failure status (connect_timeout, timeout, resolve_failed, "
        "connect_refused, closed, smtp_error) never got that far and is excluded rather than silently treated "
        "as \"not offered\" (Standing Rule 9). The TLS-handshake-completed metric is unaffected -- its own "
        "denominator was already just the domains where STARTTLS was offered.",
        f"- Status breakdown: {dict(status_count)}", "",
        "## By sector", "", md_table(by_cat), "",
        "## By verification tier", "", md_table(by_tier), "",
        "## Largest mail servers by number of domains", "",
        "| mx host | domains | status | STARTTLS | TLS version |", "|---|---|---|---|---|",
    ] + [f"| {h} | {len(ds)} | {results.get(h, {}).get('status', 'not_scanned')} | "
         f"{results.get(h, {}).get('starttls_offered', '')} | {results.get(h, {}).get('tls_version', '')} |"
         for h, ds in top_hosts] + [""])
    with open(os.path.join(OUT_TABLES, "phase_c4_report.md"), "w", encoding="utf-8") as f:
        f.write(md)

    def fmt(v):
        return "–" if v is None else f"{v}%"

    print(f"\nDomains with MX {len(domain_to_host)} | mail servers {len(by_host)} | status {dict(status_count)}")
    print(f"  STARTTLS offered  {a['starttls_offered_n']}/{a['starttls_offered_den']}  "
          f"dom {fmt(a['starttls_offered_dom_pct'])}  srv {fmt(a['starttls_offered_srv_pct'])}")
    print(f"  TLS handshake ok  {a['tls_handshake_ok_n']}/{a['tls_handshake_ok_den']}  "
          f"dom {fmt(a['tls_handshake_ok_dom_pct'])}  srv {fmt(a['tls_handshake_ok_srv_pct'])}")
    print("Largest mail servers:", ", ".join(f"{h}({len(ds)})" for h, ds in top_hosts[:5]))
    print(f"Wrote: {PROCESSED_DIR}/phase_c4_domains.csv and results/tables/phase_c4_*")


if __name__ == "__main__":
    main()