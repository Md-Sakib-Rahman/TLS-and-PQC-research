#!/usr/bin/env python3
"""
Phase A, step 4: attrition report -- how many corpus domains survive each stage,
by sector category and by verification tier.

Funnel: scanned -> resolves -> port 443 open (= live, eligible for the TLS scan).
Percentages use SCANNED domains as the denominator, so an incomplete run is never
silently treated as "dead". Inconclusive (timeout/SERVFAIL) is reported separately.

Outputs (results/tables/):
  phase_a_attrition_by_category.csv
  phase_a_attrition_by_tier.csv
  phase_a_attrition_report.md

Usage: python measurement/phase_a_liveness/a4_attrition_report.py [--run-id ID]
"""

import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import BASE, PROCESSED_DIR, read_run_meta, resolve_run_dir

OUT_DIR = os.path.join(BASE, "results", "tables")
COLS = ["group", "corpus_total", "scanned", "resolves", "resolves_pct", "nxdomain", "no_address",
        "inconclusive", "open_443", "open_443_pct", "open_pct_of_resolving", "closed", "no_response"]


def pct(n, d):
    return round(100 * n / d, 1) if d else 0.0


def summarise(rows, key):
    groups = defaultdict(list)
    for r in rows:
        groups[r[key]].append(r)
    out = []
    for name, rs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        out.append(summary_row(name, rs))
    out.append(summary_row("ALL", rows))
    return out


def summary_row(name, rs):
    scanned = [r for r in rs if r["dns_status"] != "not_scanned"]
    n = len(scanned)
    c = lambda field, val: sum(r[field] == val for r in scanned)
    resolves, opened = c("dns_status", "resolves"), c("port443", "open")
    return {"group": name, "corpus_total": len(rs), "scanned": n,
            "resolves": resolves, "resolves_pct": pct(resolves, n),
            "nxdomain": c("dns_status", "nxdomain"), "no_address": c("dns_status", "no_address"),
            "inconclusive": c("dns_status", "inconclusive"),
            "open_443": opened, "open_443_pct": pct(opened, n), "open_pct_of_resolving": pct(opened, resolves),
            "closed": c("port443", "closed"), "no_response": c("port443", "no_response")}


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def md_table(rows):
    lines = ["| " + " | ".join(COLS) + " |", "|" + "---|" * len(COLS)]
    lines += ["| " + " | ".join(str(r[c]) for c in COLS) + " |" for r in rows]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", help="run folder (default: newest)")
    args = ap.parse_args()

    run_dir = resolve_run_dir(args.run_id)
    meta = read_run_meta(run_dir)
    path = os.path.join(PROCESSED_DIR, "liveness_all.csv")
    if not os.path.exists(path):
        sys.exit("ERROR: liveness_all.csv not found. Run a3_build_live_list.py first.")
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    by_cat, by_tier = summarise(rows, "category"), summarise(rows, "tier")
    os.makedirs(OUT_DIR, exist_ok=True)
    write_csv(os.path.join(OUT_DIR, "phase_a_attrition_by_category.csv"), by_cat)
    write_csv(os.path.join(OUT_DIR, "phase_a_attrition_by_tier.csv"), by_tier)

    not_scanned = sum(r["dns_status"] == "not_scanned" for r in rows)
    warn = f"\n**WARNING: {not_scanned} corpus domains have no DNS result (incomplete run). Percentages cover scanned domains only.**\n" if not_scanned else ""
    report = (f"# Phase A attrition report\n\n"
              f"- Run: `{os.path.basename(run_dir)}`\n"
              f"- Corpus file: `{meta.get('input', {}).get('file')}` (sha256 `{meta.get('input', {}).get('sha256')}`)\n"
              f"- Vantage point: {meta.get('environment', {}).get('vantage_point') or '(not recorded)'}\n"
              f"- Resolvers: {', '.join(meta.get('dns', {}).get('config', {}).get('nameservers', []))}\n{warn}\n"
              f"Percent columns use scanned domains as the denominator, except `open_pct_of_resolving`. "
              f"`inconclusive` (timeout/SERVFAIL) is NOT counted as dead.\n\n"
              f"## By sector category\n\n{md_table(by_cat)}\n\n## By verification tier\n\n{md_table(by_tier)}\n")
    with open(os.path.join(OUT_DIR, "phase_a_attrition_report.md"), "w", encoding="utf-8") as f:
        f.write(report)
    print(report)


if __name__ == "__main__":
    main()
