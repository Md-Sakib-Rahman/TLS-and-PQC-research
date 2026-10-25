#!/usr/bin/env python3
"""
Phase B, step 3: turn the raw Phase B scan output into analysis tables.

Inputs (all for one --run-id):
  data/measurement/processed/live_domains.csv    the 7,999-domain live set from Phase A (a3)
  data/measurement/runs/<run_id>/raw/tls.jsonl   b1: TLS / post-quantum handshake results
  data/measurement/runs/<run_id>/raw/http.jsonl  b2 (+ merged backfill): HTTP header results

Outputs:
  data/measurement/processed/phase_b_domains.csv      one flat row per live domain
  results/tables/phase_b_by_category.csv              every metric, per sector category
  results/tables/phase_b_by_tier.csv                  every metric, per verification tier
  results/tables/phase_b_top_servers.csv              the largest shared-hosting IPs
  results/tables/phase_b_by_category_excl_service.csv same as by_category, service hostnames removed
  results/tables/phase_b_by_tier_excl_service.csv     same as by_tier, service hostnames removed
  results/tables/phase_b_report.md                    human-readable summary

TWO VIEWS OF EVERY METRIC
  *_dom_pct   per domain: each domain counts once.
  *_srv_pct   per server: each IP counts once in total. Within a group, an IP's weight of 1 is
              split equally across its domains that are in that metric's denominator, so a host
              serving 1,219 domains counts the same as a host serving one. Needed because shared
              hosting makes domains non-independent (Phase A: 7,999 live domains on ~2,000 IPs).
  Server = the IP recorded in Phase A. A CDN IP shared by unrelated customers counts as one
  server; that is reasonable for TLS settings, which the CDN edge controls.

MISSING DATA IS NEVER COUNTED AS A FAILURE
  - A live domain with no tls.jsonl record is "not_scanned" and excluded from TLS denominators.
  - A live domain with no http.jsonl record is "pending" (e.g. the rate-limited 103.157.135.180
    cluster) and excluded from HTTP denominators. For HSTS the per-domain figure is also given
    as bounds: low = if every pending domain lacks HSTS, high = if every pending domain has it.
  - A domain that WAS scanned but failed (timeout, TLS error) is a real result, kept as such.

SERVICE HOSTNAMES (sensitivity check)
  Hosting control panels and mail setups auto-create hostnames such as cpanel.x, webmail.x,
  mail.x, webdisk.x, cpcontacts.x, autodiscover.x. They are real live HTTPS endpoints but not
  what a reader means by "an institution's website", and they cluster on shared servers.
  is_service_hostname = the FIRST label is in SERVICE_LABELS. This is an approximate heuristic
  (it misses unusual names like webmail2.x), so the paper should call it approximate. They are
  never removed from the data: every table is produced twice, with and without them.

SMALL GROUPS
  Groups with fewer than MIN_N domains in a metric's denominator are shown as raw counts
  ("k/n") in the markdown report, not percentages (banking, telecom, defence are tiny).

Usage (from project root):
    python measurement/phase_b_tls/b3_parse_results.py --run-id run_2026-09-19
"""

import argparse
import csv
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import BASE, PROCESSED_DIR, read_jsonl, resolve_run_dir

OUT_TABLES = os.path.join(BASE, "results", "tables")
MIN_N = 30
PQ_CLASSES = ["pq_default", "pq_capable_not_default", "not_capable", "no_tls13", "unknown"]
SERVICE_LABELS = {"cpanel", "webmail", "webdisk", "whm", "cpcontacts", "cpcalendars", "autodiscover",
                  "autoconfig", "mail", "ftp", "smtp", "imap", "pop", "mx"}


def is_service_hostname(domain):
    return domain.split(".", 1)[0].lower() in SERVICE_LABELS

DOMAIN_COLS = [
    "domain", "category", "tier", "ip", "domains_on_ip", "is_service_hostname",
    "tls_status", "tls_version", "cipher", "group", "pq_class", "pq_intolerant", "legacy_only",
    "accepts_tls_1_0_or_1_1",
    "cert_trusted", "cert_expired", "cert_self_signed", "cert_hostname_match", "cert_key_type",
    "cert_key_bits", "cert_sig_hash", "cert_issuer_o", "cert_serial_non_positive",
    "http_status", "http_source", "http_status_code", "hsts_present", "hsts_max_age",
    "hsts_include_subdomains", "hsts_preload", "waf_detected", "waf_vendors",
]


# ---------------------------------------------------------------- loading

def load_latest(path):
    """{domain: record}; if a domain appears more than once, keep the record with the latest ts."""
    by_domain, dupes = {}, 0
    for r in read_jsonl(path):
        d = r.get("domain")
        if not d:
            continue
        if d in by_domain:
            dupes += 1
            if (r.get("ts") or "") < (by_domain[d].get("ts") or ""):
                continue
        by_domain[d] = r
    return by_domain, dupes


def flatten(live_row, n_on_ip, t, h):
    cert = (t or {}).get("cert") or {}
    hsts = (h or {}).get("hsts") or {}
    waf = (h or {}).get("waf") or {}
    return {
        "domain": live_row["domain"], "category": live_row["category"], "tier": live_row["tier"],
        "ip": live_row["ip"], "domains_on_ip": n_on_ip,
        "is_service_hostname": is_service_hostname(live_row["domain"]),
        "tls_status": t["status"] if t else "not_scanned",
        "tls_version": t.get("tls_version") if t else None,
        "cipher": t.get("cipher") if t else None,
        "group": t.get("group") if t else None,
        "pq_class": t.get("pq_class", "unknown") if t else None,
        "pq_intolerant": t.get("pq_intolerant") if t else None,
        "legacy_only": t.get("legacy_only") if t else None,
        "accepts_tls_1_0_or_1_1": t.get("accepts_tls_1_0_or_1_1") if t else None,
        "cert_trusted": cert.get("trusted"),
        "cert_expired": cert.get("expired"),
        "cert_self_signed": cert.get("self_signed"),
        "cert_hostname_match": cert.get("hostname_match"),
        "cert_key_type": cert.get("key_type"),
        "cert_key_bits": cert.get("key_bits"),
        "cert_sig_hash": cert.get("sig_hash"),
        "cert_issuer_o": cert.get("issuer_o"),
        "cert_serial_non_positive": cert.get("serial_number_non_positive"),   # absent in pre-fix records
        "http_status": h["status"] if h else "pending",
        "http_source": (h.get("source") or "primary") if h else None,
        "http_status_code": h.get("status_code") if h else None,
        "hsts_present": hsts.get("present") if h and h.get("status") == "ok" else None,
        "hsts_max_age": hsts.get("max_age"),
        "hsts_include_subdomains": hsts.get("include_subdomains"),
        "hsts_preload": hsts.get("preload"),
        "waf_detected": waf.get("detected") if h and h.get("status") == "ok" else None,
        "waf_vendors": "|".join(waf.get("vendors") or []),
    }


# ---------------------------------------------------------------- metrics

def tls_scanned(r):
    return r["tls_status"] != "not_scanned"


def http_ok(r):
    return r["http_status"] == "ok"


def has_cert(r):
    return r["cert_trusted"] is not None


# (name, denominator predicate, numerator predicate)
METRICS = [
    ("tls_handshake_ok", tls_scanned, lambda r: r["tls_status"] == "ok"),
    ("tls13", lambda r: r["tls_status"] == "ok", lambda r: r["tls_version"] == "TLSv1.3"),
] + [(c, tls_scanned, (lambda c: lambda r: r["pq_class"] == c)(c)) for c in PQ_CLASSES] + [
    ("accepts_tls_1_0_or_1_1", lambda r: r["accepts_tls_1_0_or_1_1"] is not None,
     lambda r: r["accepts_tls_1_0_or_1_1"] is True),
    ("pq_intolerant", lambda r: r["tls_status"] == "ok", lambda r: r["pq_intolerant"] is True),
    ("legacy_only", lambda r: r["tls_status"] == "ok", lambda r: r["legacy_only"] is True),
    ("cert_trusted", has_cert, lambda r: r["cert_trusted"] is True),
    ("cert_expired", has_cert, lambda r: r["cert_expired"] is True),
    ("cert_self_signed", has_cert, lambda r: r["cert_self_signed"] is True),
    ("cert_hostname_mismatch", has_cert, lambda r: r["cert_hostname_match"] is False),
    ("cert_rsa_below_2048", lambda r: r["cert_key_type"] == "RSA" and r["cert_key_bits"],
     lambda r: r["cert_key_bits"] < 2048),
    ("http_ok", lambda r: r["http_status"] != "pending", http_ok),
    ("hsts", http_ok, lambda r: r["hsts_present"] is True),
    ("waf_detected", http_ok, lambda r: r["waf_detected"] is True),
]


def pct(n, d):
    return round(100.0 * n / d, 1) if d else None


def server_weighted(rows, den, num):
    """Share of servers: each IP's weight of 1 is split across its rows in the denominator."""
    per_ip = defaultdict(list)
    for r in rows:
        if den(r):
            per_ip[r["ip"]].append(r)
    if not per_ip:
        return None, 0
    total = sum(sum(1 for r in rs if num(r)) / len(rs) for rs in per_ip.values())
    return round(100.0 * total / len(per_ip), 1), len(per_ip)


def summarize(name, rows):
    out = {"group": name, "domains": len(rows), "servers": len({r["ip"] for r in rows})}
    for m, den, num in METRICS:
        d = [r for r in rows if den(r)]
        n = sum(1 for r in d if num(r))
        out[f"{m}_n"], out[f"{m}_den"] = n, len(d)
        out[f"{m}_dom_pct"] = pct(n, len(d))
        out[f"{m}_srv_pct"], out[f"{m}_srv_den"] = server_weighted(rows, den, num)
    pending = sum(1 for r in rows if r["http_status"] == "pending")
    ok = out["hsts_den"]
    present = out["hsts_n"]
    out["http_pending"] = pending
    out["hsts_dom_pct_low"] = pct(present, ok + pending)
    out["hsts_dom_pct_high"] = pct(present + pending, ok + pending)
    return out


def group_table(rows, key):
    groups = defaultdict(list)
    for r in rows:
        groups[r[key]].append(r)
    table = [summarize(g, rs) for g, rs in sorted(groups.items(), key=lambda kv: -len(kv[1]))]
    table.append(summarize("ALL", rows))
    return table


def top_servers(rows, n=15):
    per_ip = defaultdict(list)
    for r in rows:
        per_ip[r["ip"]].append(r)
    out = []
    for ip, rs in sorted(per_ip.items(), key=lambda kv: -len(kv[1]))[:n]:
        cats = Counter(r["category"] for r in rs)
        pq = Counter(r["pq_class"] for r in rs if r["pq_class"])
        out.append({
            "ip": ip, "domains": len(rs),
            "categories": "; ".join(f"{k}={v}" for k, v in cats.most_common()),
            "pq_classes": "; ".join(f"{k}={v}" for k, v in pq.most_common()),
            "accepts_tls_1_0_or_1_1": sum(1 for r in rs if r["accepts_tls_1_0_or_1_1"] is True),
            "http_ok": sum(1 for r in rs if r["http_status"] == "ok"),
            "http_pending": sum(1 for r in rs if r["http_status"] == "pending"),
            "hsts_present": sum(1 for r in rs if r["hsts_present"] is True),
        })
    return out


def crosstab_old_versions(rows):
    t = defaultdict(Counter)
    for r in rows:
        if tls_scanned(r):
            t[r["pq_class"]][str(r["accepts_tls_1_0_or_1_1"])] += 1
    return t


# ---------------------------------------------------------------- writing

def write_csv(path, rows, cols=None):
    cols = cols or list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def cell(row, m):
    """'dom% / srv%', or 'k/n' when the denominator is small."""
    n, den = row[f"{m}_n"], row[f"{m}_den"]
    if den == 0:
        return "–"
    if den < MIN_N:
        return f"{n}/{den}"
    return f"{row[f'{m}_dom_pct']} / {row[f'{m}_srv_pct']}"


def md_table(table, metrics, labels):
    head = "| group | domains | servers | " + " | ".join(labels) + " |"
    sep = "|" + "---|" * (3 + len(labels))
    body = [f"| {r['group']} | {r['domains']} | {r['servers']} | " + " | ".join(cell(r, m) for m in metrics) + " |"
            for r in table]
    return "\n".join([head, sep] + body)


def report(run_id, rows, by_cat, by_tier, top, xtab, notes, by_cat_x, n_service):
    core = ["tls13", "pq_default", "pq_capable_not_default", "not_capable", "accepts_tls_1_0_or_1_1"]
    core_l = ["TLS 1.3", "PQ default", "PQ capable, not default", "not capable", "accepts TLS 1.0/1.1"]
    cert = ["cert_trusted", "cert_expired", "cert_self_signed", "cert_hostname_mismatch", "cert_rsa_below_2048"]
    cert_l = ["trusted", "expired", "self-signed", "hostname mismatch", "RSA < 2048"]
    http = ["http_ok", "hsts", "waf_detected"]
    http_l = ["HTTP response", "HSTS", "WAF/CDN signature"]
    allrow = by_cat[-1]
    lines = [
        f"# Phase B results (`{run_id}`)", "",
        f"- Live domains: {len(rows)} on {allrow['servers']} distinct IPs.",
        "- Cells show **per-domain % / per-server %** (each IP counts once in total). "
        f"Groups with fewer than {MIN_N} domains in the denominator show raw counts `k/n`.",
        "- Missing data is excluded from denominators, never counted as failure "
        "(TLS `not_scanned`; HTTP `pending`).",
    ] + [f"- {n}" for n in notes] + [
        "", "## TLS and post-quantum key exchange, by sector", "", md_table(by_cat, core, core_l),
        "", "## TLS and post-quantum key exchange, by verification tier", "", md_table(by_tier, core, core_l),
        "", f"## Sensitivity: excluding {n_service} auto-created service hostnames", "",
        "Same metrics with cpanel/webmail/mail/webdisk-style hostnames removed (approximate, first-label "
        "heuristic). If a figure moves a lot between this table and the one above, service hostnames are "
        "driving it.", "", md_table(by_cat_x, core + ["hsts"], core_l + ["HSTS"]),
        "", "## Certificates, by sector", "", md_table(by_cat, cert, cert_l),
        "", "## HTTP headers, by sector", "", md_table(by_cat, http, http_l),
        "", "HSTS per-domain bounds (pending domains assumed all-absent / all-present):", "",
        "| group | pending | HSTS low % | HSTS high % |", "|---|---|---|---|",
    ] + [f"| {r['group']} | {r['http_pending']} | {r['hsts_dom_pct_low']} | {r['hsts_dom_pct_high']} |"
         for r in by_cat] + [
        "", "## Old-version acceptance by PQ class (domain counts)", "",
        "| pq_class | accepts TLS 1.0/1.1 | refuses | no clear answer |", "|---|---|---|---|",
    ] + [f"| {c} | {xtab[c]['True']} | {xtab[c]['False']} | {xtab[c]['None']} |" for c in PQ_CLASSES if c in xtab] + [
        "", "## Largest shared-hosting IPs", "",
        "| ip | domains | categories | pq classes | HTTP ok | HTTP pending |", "|---|---|---|---|---|---|",
    ] + [f"| {s['ip']} | {s['domains']} | {s['categories']} | {s['pq_classes']} | {s['http_ok']} | {s['http_pending']} |"
         for s in top] + [""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()

    run_dir = resolve_run_dir(args.run_id)
    live_path = os.path.join(PROCESSED_DIR, "live_domains.csv")
    with open(live_path, newline="", encoding="utf-8") as f:
        live = list(csv.DictReader(f))
    tls, tls_dupes = load_latest(os.path.join(run_dir, "raw", "tls.jsonl"))
    http, http_dupes = load_latest(os.path.join(run_dir, "raw", "http.jsonl"))

    live_set = {r["domain"] for r in live}
    on_ip = Counter(r["ip"] for r in live)
    rows = [flatten(r, on_ip[r["ip"]], tls.get(r["domain"]), http.get(r["domain"])) for r in live]

    notes = []
    missing_tls = sum(1 for r in rows if r["tls_status"] == "not_scanned")
    pending_http = sum(1 for r in rows if r["http_status"] == "pending")
    backfilled = sum(1 for r in rows if r["http_source"] == "secondary_vantage")
    extra_tls, extra_http = len(set(tls) - live_set), len(set(http) - live_set)
    if missing_tls:
        notes.append(f"{missing_tls} live domains have no TLS record (not_scanned).")
    if pending_http:
        notes.append(f"{pending_http} live domains have no HTTP record yet (pending).")
    if backfilled:
        notes.append(f"{backfilled} HTTP records came from a secondary Bangladeshi vantage point (backfill).")
    if tls_dupes or http_dupes:
        notes.append(f"Duplicate records resolved by latest timestamp: tls={tls_dupes}, http={http_dupes}.")
    if extra_tls or extra_http:
        notes.append(f"Records for domains outside the live set were ignored: tls={extra_tls}, http={extra_http}.")

    by_cat, by_tier = group_table(rows, "category"), group_table(rows, "tier")
    web = [r for r in rows if not r["is_service_hostname"]]
    n_service = len(rows) - len(web)
    by_cat_x, by_tier_x = group_table(web, "category"), group_table(web, "tier")
    top, xtab = top_servers(rows), crosstab_old_versions(rows)

    os.makedirs(OUT_TABLES, exist_ok=True)
    write_csv(os.path.join(PROCESSED_DIR, "phase_b_domains.csv"), rows, DOMAIN_COLS)
    write_csv(os.path.join(OUT_TABLES, "phase_b_by_category.csv"), by_cat)
    write_csv(os.path.join(OUT_TABLES, "phase_b_by_tier.csv"), by_tier)
    write_csv(os.path.join(OUT_TABLES, "phase_b_top_servers.csv"), top)
    write_csv(os.path.join(OUT_TABLES, "phase_b_by_category_excl_service.csv"), by_cat_x)
    write_csv(os.path.join(OUT_TABLES, "phase_b_by_tier_excl_service.csv"), by_tier_x)
    md = report(args.run_id, rows, by_cat, by_tier, top, xtab, notes, by_cat_x, n_service)
    with open(os.path.join(OUT_TABLES, "phase_b_report.md"), "w", encoding="utf-8") as f:
        f.write(md)

    a = by_cat[-1]
    print(f"Run: {args.run_id} | live domains {len(rows)} | servers {a['servers']}")
    for n in notes:
        print(f"  note: {n}")
    for c in PQ_CLASSES:
        print(f"  {c:24s} {a[c + '_n']:5d}  dom {a[c + '_dom_pct']}%  srv {a[c + '_srv_pct']}%")
    print(f"  accepts TLS 1.0/1.1      {a['accepts_tls_1_0_or_1_1_n']:5d}  dom {a['accepts_tls_1_0_or_1_1_dom_pct']}%"
          f"  srv {a['accepts_tls_1_0_or_1_1_srv_pct']}%")
    print(f"  HSTS (of HTTP ok)        {a['hsts_n']:5d}  dom {a['hsts_dom_pct']}%  srv {a['hsts_srv_pct']}%"
          f"  | bounds with pending: {a['hsts_dom_pct_low']}-{a['hsts_dom_pct_high']}%")
    ax = by_cat_x[-1]
    print(f"Excluding {n_service} service hostnames ({ax['domains']} domains, {ax['servers']} servers):")
    for c in ("pq_default", "not_capable", "accepts_tls_1_0_or_1_1", "hsts"):
        print(f"  {c:24s} dom {a[c + '_dom_pct']}% -> {ax[c + '_dom_pct']}%   srv {a[c + '_srv_pct']}% -> {ax[c + '_srv_pct']}%")
    print(f"Wrote: {PROCESSED_DIR}/phase_b_domains.csv and results/tables/phase_b_*.csv, phase_b_report.md")


if __name__ == "__main__":
    main()