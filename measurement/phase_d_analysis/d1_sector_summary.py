#!/usr/bin/env python3
"""
Phase D, step 1: sector overview, provider-group breakdown, and PQ-adoption-vs-
certificate-trust correlation.

This is a real, runnable replacement for the empty stub at
measurement/phase_d_analysis/d1_sector_summary.py. It reads the single
already-joined per-domain table (phase_d_joined.csv, produced by joining
live_domains.csv + Phase B (phase_b_domains.csv) + Phase C1 (phase_c1_keys.csv)
+ Phase C2 (phase_c2_ciphers.csv) + Phase C3 (phase_c3_domains.csv) +
Phase C4 (phase_c4_domains.csv) on `domain`, plus a `provider_guess` column
already present in that join) and computes three real outputs. No numbers in
this script are asserted without being computed here.

Input:
  data/measurement/processed/phase_d_joined.csv   7,999 rows, one per live domain

Outputs (results/tables/):
  phase_d_sector_overview.csv       per sector category: pq_default / cert_trusted
                                     / accepts_sslv3 rates, domain-level and
                                     server-level
  phase_d_provider_breakdown.csv    per hosting/CDN provider group: domain count
                                     + pq_default rate
  phase_d_pq_vs_trust.csv           cert_trusted rate, split by whether the
                                     domain is pq_default or not
  phase_d_sector_overview_report.md human-readable summary of all three

METHODOLOGY NOTE ON THE SERVER-LEVEL VIEW
  TLS/cert configuration is usually set per IP, but is NOT perfectly constant
  across every domain sharing an IP (SNI-based virtual hosting, or a shared
  host running different vhosts per domain, can differ). Checked directly on
  this data: 43 of 1,861 IPs (2.3%) show more than one distinct pq_class among
  their domains, 163 of 1,861 (8.8%) show more than one distinct cert_trusted
  value. So instead of assuming one IP = one fixed value (which would be
  wrong for those IPs), the server-level rate for an IP is that IP's own
  domain-level rate (mean of the metric across its domains in the
  denominator), and the server-level percentage for a group is the unweighted
  mean of those per-IP rates across all distinct IPs in the group. This
  matches the "each IP counts once in total" principle already documented in
  b3_parse_results.py (Phase B) and is more defensible than picking one
  domain's value per IP.

MIN_N
  Groups (sector categories, provider groups) with fewer than MIN_N domains in
  a metric's denominator are reported as raw counts "k/n", not percentages,
  consistent with Standing Rule 11 of this project.
"""
import argparse
import os
import pandas as pd

MIN_N = 30

INPUT_DEFAULT = "data/measurement/processed/phase_d_joined.csv"
OUT_DIR_DEFAULT = "results/tables"


def pct(n, d):
    return round(100 * n / d, 1) if d else None


def domain_server_rate(df, metric_col, true_value=True):
    """Return (n, den, dom_pct, srv_n_equiv, srv_den, srv_pct) for a boolean-ish
    metric column, where NaN rows are excluded from the denominator entirely
    (never counted as a negative)."""
    sub = df[df[metric_col].notna()]
    den = len(sub)
    n = int((sub[metric_col] == true_value).sum())
    dom_pct = pct(n, den)

    # server-level: each IP's own domain-level rate, then unweighted mean across IPs
    srv_den = sub["ip"].nunique()
    if srv_den == 0:
        return n, den, dom_pct, 0, 0, None
    per_ip_rate = sub.groupby("ip")[metric_col].apply(lambda s: (s == true_value).mean())
    srv_pct = round(100 * per_ip_rate.mean(), 1)
    return n, den, dom_pct, srv_den, srv_den, srv_pct


def cell(n, den, dom_pct, srv_den, srv_pct):
    if den < MIN_N:
        return f"{n}/{den}"
    return f"{dom_pct}% / {srv_pct}%"


def sector_overview(df):
    rows = []
    for cat, g in df.groupby("category"):
        row = {"category": cat, "domains": len(g), "servers": g["ip"].nunique()}
        for metric, col, true_val in [
            ("pq_default", "pq_class", "pq_default"),
            ("cert_trusted", "cert_trusted", True),
            ("accepts_sslv3", "c2_accepts_sslv3", True),
        ]:
            n, den, dom_pct, srv_den, _, srv_pct = domain_server_rate(g, col, true_val)
            row[f"{metric}_n"] = n
            row[f"{metric}_den"] = den
            row[f"{metric}_dom_pct"] = dom_pct
            row[f"{metric}_srv_den"] = srv_den
            row[f"{metric}_srv_pct"] = srv_pct
        rows.append(row)
    allrow = {"category": "ALL", "domains": len(df), "servers": df["ip"].nunique()}
    for metric, col, true_val in [
        ("pq_default", "pq_class", "pq_default"),
        ("cert_trusted", "cert_trusted", True),
        ("accepts_sslv3", "c2_accepts_sslv3", True),
    ]:
        n, den, dom_pct, srv_den, _, srv_pct = domain_server_rate(df, col, true_val)
        allrow[f"{metric}_n"] = n
        allrow[f"{metric}_den"] = den
        allrow[f"{metric}_dom_pct"] = dom_pct
        allrow[f"{metric}_srv_den"] = srv_den
        allrow[f"{metric}_srv_pct"] = srv_pct
    rows.append(allrow)
    return pd.DataFrame(rows)


def provider_breakdown(df):
    rows = []
    tagged = df[df["provider_guess"].notna()]
    for prov, g in tagged.groupby("provider_guess"):
        n, den, dom_pct, srv_den, _, srv_pct = domain_server_rate(g, "pq_class", "pq_default")
        rows.append({
            "provider": prov,
            "domains": len(g),
            "servers": g["ip"].nunique(),
            "pq_default_n": n,
            "pq_default_den": den,
            "pq_default_dom_pct": dom_pct,
            "pq_default_srv_pct": srv_pct,
        })
    out = pd.DataFrame(rows).sort_values("domains", ascending=False)
    untagged = len(df) - len(tagged)
    return out, untagged


def pq_vs_trust(df):
    sub = df[df["cert_trusted"].notna() & df["pq_class"].notna()].copy()
    sub["is_pq_default"] = sub["pq_class"] == "pq_default"
    rows = []
    for is_pq, g in sub.groupby("is_pq_default"):
        n, den, dom_pct, srv_den, _, srv_pct = domain_server_rate(g, "cert_trusted", True)
        rows.append({
            "pq_default": bool(is_pq),
            "domains": len(g),
            "servers": g["ip"].nunique(),
            "cert_trusted_n": n,
            "cert_trusted_den": den,
            "cert_trusted_dom_pct": dom_pct,
            "cert_trusted_srv_pct": srv_pct,
        })
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=INPUT_DEFAULT)
    ap.add_argument("--out-dir", default=OUT_DIR_DEFAULT)
    args = ap.parse_args()

    df = pd.read_csv(args.input, low_memory=False)
    os.makedirs(args.out_dir, exist_ok=True)

    overview = sector_overview(df)
    overview.to_csv(os.path.join(args.out_dir, "phase_d_sector_overview.csv"), index=False)

    provs, untagged = provider_breakdown(df)
    provs.to_csv(os.path.join(args.out_dir, "phase_d_provider_breakdown.csv"), index=False)

    trust = pq_vs_trust(df)
    trust.to_csv(os.path.join(args.out_dir, "phase_d_pq_vs_trust.csv"), index=False)

    lines = [
        f"# Phase D sector summary (from `{args.input}`, {len(df)} live domains, "
        f"{df['ip'].nunique()} distinct IPs)",
        "",
        "## Sector overview (PQ-default / cert-trusted / accepts-SSLv3, domain% / server%)",
        "",
        "| category | domains | servers | pq_default | cert_trusted | accepts_sslv3 |",
        "|---|---|---|---|---|---|",
    ]
    for _, r in overview.iterrows():
        lines.append(
            f"| {r['category']} | {r['domains']} | {r['servers']} | "
            f"{cell(r['pq_default_n'], r['pq_default_den'], r['pq_default_dom_pct'], r['pq_default_srv_den'], r['pq_default_srv_pct'])} | "
            f"{cell(r['cert_trusted_n'], r['cert_trusted_den'], r['cert_trusted_dom_pct'], r['cert_trusted_srv_den'], r['cert_trusted_srv_pct'])} | "
            f"{cell(r['accepts_sslv3_n'], r['accepts_sslv3_den'], r['accepts_sslv3_dom_pct'], r['accepts_sslv3_srv_den'], r['accepts_sslv3_srv_pct'])} |"
        )

    lines += [
        "",
        f"## Provider-group breakdown ({untagged} of {len(df)} domains have no provider match; "
        "a long tail of unidentified/smaller providers is not individually broken out)",
        "",
        "| provider | domains | servers | pq_default |",
        "|---|---|---|---|",
    ]
    for _, r in provs.iterrows():
        lines.append(
            f"| {r['provider']} | {r['domains']} | {r['servers']} | "
            f"{cell(r['pq_default_n'], r['pq_default_den'], r['pq_default_dom_pct'], None, r['pq_default_srv_pct'])} |"
        )

    lines += [
        "",
        "## Certificate trust by PQ adoption (not formally tested for causation)",
        "",
        "| pq_default | domains | servers | cert_trusted |",
        "|---|---|---|---|",
    ]
    for _, r in trust.iterrows():
        lines.append(
            f"| {r['pq_default']} | {r['domains']} | {r['servers']} | "
            f"{cell(r['cert_trusted_n'], r['cert_trusted_den'], r['cert_trusted_dom_pct'], None, r['cert_trusted_srv_pct'])} |"
        )

    report = "\n".join(lines)
    with open(os.path.join(args.out_dir, "phase_d_sector_overview_report.md"), "w", encoding="utf-8") as f:
        f.write(report)

    print(report)


if __name__ == "__main__":
    main()