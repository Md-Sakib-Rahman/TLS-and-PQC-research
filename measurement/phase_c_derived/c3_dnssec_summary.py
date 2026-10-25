#!/usr/bin/env python3
"""
Phase C, step 3: DNSSEC summary from data Phase A already collected. No network access.

WHAT THE DATA IS
  a1 asked public validating resolvers (1.1.1.1, 8.8.8.8) for every corpus name with the DNSSEC-OK bit
  set, and recorded the AD ("authenticated data") flag on the A/AAAA answer. AD = True means the resolver
  validated the answer against a full chain of trust from the root: the name sits in a signed zone with a
  secure delegation. That is the best end-to-end DNSSEC signal available and needs no new queries.
  a1 also recorded DS and DNSKEY at each queried NAME (not at the zone apex), so those two columns only
  carry information for names that ARE apexes (for example jnu.ac.bd itself).

WHAT AD = False MEANS, AND DOES NOT
  It means: an unsigned zone, OR a signed zone with no DS in its parent (an "island"), OR an algorithm the
  resolver does not support. It does NOT mean "broken": a zone whose signatures are invalid makes a
  validating resolver answer SERVFAIL, so those names sit in Phase A's "inconclusive" bucket and are not
  in this analysis at all. Measuring broken DNSSEC would need a new pass with the CD flag (a possible
  c3b, only if the numbers justify it).

UNIT OF ANALYSIS: THE REGISTERED-DOMAIN PROXY
  DNSSEC is a per-ZONE property, and one institution can have hundreds of names in one zone, so counting
  names would repeat the shared-hosting problem of Phase B. Names are therefore grouped by a proxy for
  their zone: the label directly under a `.bd` suffix (jnu.ac.bd, pabna.gov.bd, example.com.bd).
  Suffixes are KNOWN_SUFFIXES plus any two-label `.xx.bd` that appears in the corpus with at least
  MIN_NAMES names under at least MIN_THIRD distinct third labels (printed so it can be checked).
  It is a proxy: a real zone cut can sit lower (a delegated department), so treat zone counts as
  approximate and say so in the paper.

ZONE STATUS (per registered domain, from its resolving names)
  validated        at least one name has AD = True   (validated_all / validated_some tell if all of them)
  signed_no_chain  no name validated, but the apex name is in the corpus and publishes DNSKEY or DS
                   (signed, but not authenticated: island of security or unsupported algorithm)
  unsigned         neither. Note "unsigned" also holds zones whose apex is not in the corpus, where
                   nothing about signing could be seen: a lower bound on signing, not proof of absence.

TWO POPULATIONS
  resolving   every name that resolved in Phase A (DNS-level view)
  live        the Phase B set (resolves AND port 443 open); zones are rebuilt from those names only

Outputs:
  data/measurement/processed/phase_c3_domains.csv            one row per resolving name
  data/measurement/processed/phase_c3_zones.csv              one row per registered-domain proxy
  results/tables/phase_c3_by_category_{resolving,live}.csv, phase_c3_by_tier_{resolving,live}.csv
  results/tables/phase_c3_report.md

Usage (from project root):
    python measurement/phase_c_derived/c3_dnssec_summary.py [--run-id run_2026-09-19]
"""

import argparse
import csv
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import PROCESSED_DIR, read_run_meta, resolve_run_dir
from measurement.phase_b_tls.b3_parse_results import OUT_TABLES, pct, write_csv

KNOWN_SUFFIXES = {"ac.bd", "com.bd", "edu.bd", "gov.bd", "info.bd", "mil.bd", "net.bd", "org.bd", "sw.bd", "tv.bd", "co.bd"}
MIN_NAMES, MIN_THIRD = 20, 10


def detect_suffixes(names, min_names=MIN_NAMES, min_third=MIN_THIRD):
    third, count = defaultdict(set), Counter()
    for n in names:
        labels = n.lower().rstrip(".").split(".")
        if len(labels) >= 3 and labels[-1] == "bd":
            s = ".".join(labels[-2:])
            count[s] += 1
            third[s].add(labels[-3])
    return {s for s in count if count[s] >= min_names and len(third[s]) >= min_third}


def registered_domain(name, suffixes):
    name = name.lower().rstrip(".")
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    return ".".join(labels[-3:]) if ".".join(labels[-2:]) in suffixes else ".".join(labels[-2:])


def to_bool(v):
    return {"True": True, "False": False}.get(v)


def build_zones(rows):
    """rows: per-name dicts with registered_domain, ad_validated, ds_present, dnskey_present, category, tier."""
    by_zone = defaultdict(list)
    for r in rows:
        by_zone[r["registered_domain"]].append(r)
    zones = []
    for z, rs in by_zone.items():
        n_ad = sum(1 for r in rs if r["ad_validated"])
        apex = next((r for r in rs if r["domain"] == z), None)
        apex_signed = bool(apex and (apex["dnskey_present"] or apex["ds_present"]))
        if n_ad:
            status = "validated"
        elif apex_signed:
            status = "signed_no_chain"
        else:
            status = "unsigned"
        cat = Counter(r["category"] for r in rs).most_common()
        tier = Counter(r["tier"] for r in rs).most_common()
        top = lambda c: sorted(c, key=lambda kv: (-kv[1], kv[0]))[0][0]
        zones.append({"registered_domain": z, "names": len(rs), "names_validated": n_ad,
                      "validated_all": n_ad == len(rs), "validated_some": 0 < n_ad < len(rs),
                      "apex_in_corpus": apex is not None, "apex_signed": apex_signed, "status": status,
                      "category": top(cat), "tier": top(tier)})
    return zones


def summarize(name, rows, zones):
    out = {"group": name, "domains": len(rows), "domains_validated": sum(1 for r in rows if r["ad_validated"]),
           "zones": len(zones)}
    out["domains_validated_pct"] = pct(out["domains_validated"], out["domains"])
    for k in ("validated", "signed_no_chain", "unsigned"):
        out[f"zones_{k}"] = sum(1 for z in zones if z["status"] == k)
        out[f"zones_{k}_pct"] = pct(out[f"zones_{k}"], len(zones))
    out["zones_validated_some"] = sum(1 for z in zones if z["validated_some"])
    return out


def table(rows, zones, key):
    groups = sorted({r[key] for r in rows}, key=lambda g: -sum(1 for r in rows if r[key] == g))
    t = [summarize(g, [r for r in rows if r[key] == g], [z for z in zones if z[key] == g]) for g in groups]
    t.append(summarize("ALL", rows, zones))
    return t


def md_table(t):
    head = ["group", "names", "names validated", "zones", "zones validated", "signed, no chain", "unsigned", "mixed*"]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in t:
        lines.append(f"| {r['group']} | {r['domains']} | {r['domains_validated']} ({r['domains_validated_pct']}%) | {r['zones']} | "
                     f"{r['zones_validated']} ({r['zones_validated_pct']}%) | {r['zones_signed_no_chain']} "
                     f"({r['zones_signed_no_chain_pct']}%) | {r['zones_unsigned']} ({r['zones_unsigned_pct']}%) | "
                     f"{r['zones_validated_some']} |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", help="only used to record which resolvers produced the AD flags")
    args = ap.parse_args()

    path = os.path.join(PROCESSED_DIR, "liveness_all.csv")
    if not os.path.exists(path):
        sys.exit(f"ERROR: {path} not found -- run a3_build_live_list.py first.")
    with open(path, newline="", encoding="utf-8") as f:
        allrows = list(csv.DictReader(f))
    resolvers = "unknown"
    if args.run_id:
        resolvers = ", ".join(read_run_meta(resolve_run_dir(args.run_id)).get("dns", {}).get("config", {}).get("nameservers", [])) or "unknown"

    res = [r for r in allrows if r["dns_status"] == "resolves"]
    suffixes = KNOWN_SUFFIXES | detect_suffixes(r["domain"] for r in res)
    rows = [{"domain": r["domain"].lower(), "category": r["category"], "tier": r["tier"],
             "registered_domain": registered_domain(r["domain"], suffixes),
             "ad_validated": to_bool(r["ad_validated"]) is True, "ds_present": to_bool(r["ds_present"]) is True,
             "dnskey_present": to_bool(r["dnskey_present"]) is True, "live": to_bool(r["live"]) is True} for r in res]
    for r in rows:
        r["is_apex"] = r["domain"] == r["registered_domain"]
    live = [r for r in rows if r["live"]]

    zones, zones_live = build_zones(rows), build_zones(live)
    os.makedirs(OUT_TABLES, exist_ok=True)
    write_csv(os.path.join(PROCESSED_DIR, "phase_c3_domains.csv"), rows,
              ["domain", "category", "tier", "registered_domain", "is_apex", "ad_validated", "ds_present", "dnskey_present", "live"])
    write_csv(os.path.join(PROCESSED_DIR, "phase_c3_zones.csv"), sorted(zones, key=lambda z: -z["names"]),
              ["registered_domain", "names", "names_validated", "validated_all", "validated_some", "apex_in_corpus",
               "apex_signed", "status", "category", "tier"])
    tabs = {}
    for pop, rs, zs in (("resolving", rows, zones), ("live", live, zones_live)):
        for key, label in (("category", "category"), ("tier", "tier")):
            tabs[(pop, key)] = table(rs, zs, key)
            write_csv(os.path.join(OUT_TABLES, f"phase_c3_by_{label}_{pop}.csv"), tabs[(pop, key)])

    ar, al = tabs[("resolving", "category")][-1], tabs[("live", "category")][-1]
    top = sorted(zones, key=lambda z: -z["names"])[:10]
    warn = []
    if rows and ar["domains_validated"] == 0:
        warn.append("NO name was validated. Either no .bd zone validates end to end, or the AD flag was not "
                    "captured. Check a known-signed name first: `dig +dnssec A cloudflare.com @1.1.1.1` must show "
                    "'ad' in the flags line.")
    md = "\n".join([
        f"# Phase C3: DNSSEC summary ({args.run_id or 'no run id'})", "",
        f"- Source: AD flag from public validating resolvers ({resolvers}), recorded by a1. {len(rows)} names resolved; "
        f"{len(live)} of them are live (Phase B set).",
        f"- Registered-domain proxy suffixes used: {', '.join(sorted(suffixes))}. Zone counts are approximate.",
        "- AD = False means unsigned, island of security, or unsupported algorithm. It does NOT mean broken: broken "
        "signatures give SERVFAIL, so those names are in Phase A's inconclusive bucket and are not counted here.",
        "- `unsigned` includes zones whose apex is not in the corpus: a lower bound on signing, not proof of absence.",
        "- *mixed = zones where some but not all names validated.", ""] + [f"- **WARNING: {w}**" for w in warn] + [
        "## All resolving names, by sector", "", md_table(tabs[("resolving", "category")]), "",
        "## All resolving names, by verification tier", "", md_table(tabs[("resolving", "tier")]), "",
        "## Live names (Phase B set), by sector", "", md_table(tabs[("live", "category")]), "",
        "## Largest zones by number of names", "", "| registered domain | names | validated | status |", "|---|---|---|---|",
    ] + [f"| {z['registered_domain']} | {z['names']} | {z['names_validated']} | {z['status']} |" for z in top] + [""])
    with open(os.path.join(OUT_TABLES, "phase_c3_report.md"), "w", encoding="utf-8") as f:
        f.write(md)

    print(f"Resolving names {ar['domains']} | validated (AD) {ar['domains_validated']} ({ar['domains_validated_pct']}%) | "
          f"zones {ar['zones']}: validated {ar['zones_validated']} ({ar['zones_validated_pct']}%), "
          f"signed-no-chain {ar['zones_signed_no_chain']}, unsigned {ar['zones_unsigned']}, mixed {ar['zones_validated_some']}")
    print(f"Live names {al['domains']} | validated {al['domains_validated']} ({al['domains_validated_pct']}%) | "
          f"zones {al['zones']}: validated {al['zones_validated']} ({al['zones_validated_pct']}%)")
    for r in tabs[("resolving", "category")][:-1]:
        print(f"  {r['group']:13s} names {r['domains']:5d} validated {r['domains_validated_pct']}% | zones {r['zones']:4d} validated {r['zones_validated_pct']}%")
    print("Largest zones:", ", ".join(f"{z['registered_domain']}({z['names']},{z['status']})" for z in top[:5]))
    for w in warn:
        print("WARNING:", w)
    print(f"Wrote: {PROCESSED_DIR}/phase_c3_*.csv and results/tables/phase_c3_*")


if __name__ == "__main__":
    main()
