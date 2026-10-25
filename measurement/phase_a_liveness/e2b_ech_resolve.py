#!/usr/bin/env python3
"""
E2b: ECH (Encrypted Client Hello) adoption via DNS HTTPS records.
(PLAN.md Section 4.17 / Section 7 Group 1 item 7)

Question: among domains in this corpus that resolve at all, how many publish
a DNS HTTPS resource record (RFC 9460, RR type 65) advertising an ECH
SvcParam (RFC 9849/9848)? How does that relate to the already-measured
DNSSEC-unsigned rate (Section 4.13: 96.1% of zones unsigned)?

This is a standalone follow-up DNS pass, NOT a full rescan: it reuses
a1_resolve_dns.py's resolver setup and io_utils helpers, and queries exactly
one new record type (HTTPS) against the population a1/a3 already proved
resolves -- the 9,028 names with dns_status == "resolves" in
data/measurement/processed/liveness_all.csv.

Per-domain status (every domain gets exactly one; never conflate these --
Standing Rule 9, "inconclusive != dead"):
  ech_present       >=1 ServiceForm (priority >= 1) HTTPS record carries an
                     ECH SvcParam, and dnspython parsed it successfully.
                     This is what "ECH adopted" means for this measurement.
  https_no_ech      >=1 ServiceForm HTTPS record exists, parsed fine, but
                     none carries ECH.
  alias_form        Only AliasForm (priority == 0) HTTPS record(s) present.
                     An AliasForm record has no params of its own -- any ECH
                     config lives at the alias target, which this pass does
                     NOT chase (that would be a second DNS hop per domain,
                     out of scope for a "targeted follow-up"). Kept as its
                     own bucket, not folded into either of the two above:
                     it is neither "no HTTPS record" nor "ECH present here".
  no_https_record   Name exists (NoAnswer/NODATA) but publishes no HTTPS
                     record of any form. The ordinary "doesn't support ECH"
                     case, but see CAVEAT below before reading it that way.
  ech_parse_error   An HTTPS record exists at the wire level, but dnspython
                     could not parse an ECH SvcParam inside it (see METHOD
                     NOTE). Neither "no ECH" nor "ECH adopted" is a
                     defensible read of this -- kept as its own bucket.
  nxdomain          HTTPS-type query itself got NXDOMAIN (should not happen
                     given the input filter, but a1's own pattern treats
                     query-type-specific NXDOMAIN as live data, not a bug,
                     so it is recorded rather than asserted away).
  servfail / timeout / error   Same meaning as a1_resolve_dns.py's buckets.

CAVEAT on "no_https_record": a HTTPS-record NODATA answer is conclusive
evidence the queried name has none -- but ECH is frequently published only
on the exact hostname a client connects to (which may be the apex, "www.",
or a service-specific name), not necessarily the corpus entry itself. This
pass queries the corpus name as-is (consistent with how a1 queries A/AAAA on
the corpus name as-is) and does NOT follow CNAME/AliasForm chains or try
sibling names. It is a lower bound on ECH presence in the DNS, not a claim
that the organization has no ECH anywhere in its zone.

METHOD NOTE: dnspython's ECHParam validates the ECH value's self-describing
length prefix (RFC 9460 SvcParam wire format: the ECHConfigList's own first
2 bytes must equal len(value)-2) during wire parsing, not just when parsing
hand-written text. A malformed or dnspython-incompatible ECH config in a
REAL server's DNS response can therefore raise dns.exception.FormError
("invalid ECHConfigList") out of resolver.resolve() on genuine network
traffic -- this was confirmed directly in this script's development by
hand-crafting a full DNS response message (header + question + answer RR)
with a deliberately invalid ECH length field and parsing it with
dns.message.from_wire(): it raises exactly this FormError, the same one a
live resolver.resolve() call would surface. This is why ech_parse_error is
its own status rather than falling into the generic "error" bucket used for
network-level failures (timeout, SERVFAIL, malformed name, etc.) -- a parse
failure means "there IS an HTTPS/ECH record here, but this measurement
could not read it", which is a materially different thing to report than
"the network didn't answer".

Zone (registered-domain) grouping reuses the exact suffix list documented
in phase_c3_report.md ("Registered-domain proxy suffixes used: ac.bd, co.bd,
com.bd, edu.bd, gov.bd, info.bd, mil.bd, net.bd, org.bd, sw.bd, tv.bd. Zone
counts are approximate.") -- c3_dnssec_summary.py's own source was not
available to import directly in this sandbox session, so the grouping
function below is a reimplementation of that documented rule, NOT an
import. It was validated, before trusting it on real data, by applying it
to the full liveness_all.csv resolving population (9,028 names) and
confirming it reproduces phase_c3_zones.csv's registered_domain/names
columns with ZERO mismatches across all 1,834 zones (checked directly
against the user's own uploaded phase_c3_zones.csv in this session). If
c3_dnssec_summary.py's actual registered_domain() function differs from
this in some case outside that file's 1,834 zones, this script's zone-level
numbers could diverge from c3's at the margin; flagged here rather than
assumed away.

Usage (from project root):
    python measurement/phase_a_liveness/e2b_ech_resolve.py --selftest
    python measurement/phase_a_liveness/e2b_ech_resolve.py --limit 200
    python measurement/phase_a_liveness/e2b_ech_resolve.py
    python measurement/phase_a_liveness/e2b_ech_resolve.py --run-id run_2026-10-15
"""

import argparse
import csv
import datetime
import os
import platform
import struct
import sys
import threading
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.version
from dns.rdtypes.svcbbase import ParamKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import (JsonlWriter, PROCESSED_DIR, done_keys, load_config,
                                         read_jsonl, resolve_run_dir, update_run_meta, utc_now)
from measurement.common.net_utils import RateLimiter

_local = threading.local()

KNOWN_SUFFIXES = {"ac.bd", "co.bd", "com.bd", "edu.bd", "gov.bd", "info.bd",
                   "mil.bd", "net.bd", "org.bd", "sw.bd", "tv.bd"}


def registered_domain(name):
    """Reimplementation of c3_dnssec_summary.py's documented zone-grouping rule
    (see METHOD NOTE in the module docstring for how this was validated)."""
    labels = name.rstrip(".").lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in KNOWN_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def make_resolver(cfg):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(cfg["nameservers"])
    r.timeout = cfg["timeout_s"]
    r.lifetime = cfg["lifetime_s"]
    r.use_edns(0, dns.flags.DO, 1232)
    return r


def classify_https_answer(ans):
    has_alias = has_service = has_ech = False
    priorities = []
    for rd in ans:
        priorities.append(rd.priority)
        if rd.priority == 0:
            has_alias = True
        else:
            has_service = True
            if ParamKey.ECH in rd.params:
                has_ech = True
    if has_ech:
        return {"status": "ech_present", "priorities": priorities}
    if has_service:
        return {"status": "https_no_ech", "priorities": priorities}
    if has_alias:
        return {"status": "alias_form", "priorities": priorities}
    return {"status": "https_no_ech", "priorities": priorities}  # defensive; should not occur


def query_https(resolver, name, retries, limiter):
    """One HTTPS-record query, with retries on timeout/SERVFAIL. Always returns a status dict.
    Mirrors a1_resolve_dns.py's query() structure, with one addition: a parse failure specific
    to a malformed ECH SvcParam is its own status (ech_parse_error), never folded into the
    generic network-error bucket -- see METHOD NOTE in the module docstring."""
    status = "error"
    for _ in range(retries + 1):
        limiter.wait()
        try:
            ans = resolver.resolve(name, "HTTPS", raise_on_no_answer=True)
            return classify_https_answer(ans)
        except dns.resolver.NXDOMAIN:
            return {"status": "nxdomain"}
        except dns.resolver.NoAnswer:
            return {"status": "no_https_record"}
        except dns.resolver.NoNameservers:
            return {"status": "servfail"}
        except dns.exception.FormError as e:
            if "ECHConfigList" in str(e):
                return {"status": "ech_parse_error", "detail": str(e)}
            return {"status": "error", "detail": "FormError: " + str(e)}
        except dns.exception.Timeout:
            status = "timeout"
        except Exception as e:
            return {"status": "error", "detail": type(e).__name__}
    return {"status": status}


def resolve_https(name, cfg, limiter, resolver_factory=None):
    if not hasattr(_local, "resolver"):
        _local.resolver = (resolver_factory or make_resolver)(cfg)
    rec = query_https(_local.resolver, name, cfg["retries"], limiter)
    rec["domain"], rec["ts"] = name, utc_now()
    return rec


# ---------------------------------------------------------------------------
# Self-test: builds synthetic HTTPS records (text-form for the normal cases,
# a hand-crafted wire-form DNS response for the malformed-ECH case, since
# that failure mode only reproduces during wire parsing -- see module
# docstring) and checks classify_https_answer()/the FormError catch produce
# the expected status, with no network access required.
# ---------------------------------------------------------------------------

class _FakeAnswer(list):
    pass


def _rdata(text):
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.HTTPS, text)


def _build_malformed_ech_wire_message():
    def param(key, value):
        return struct.pack("!HH", key, len(value)) + value
    target = dns.name.from_text("svc.example.").to_wire()
    bad_ech = struct.pack("!H", 999) + b"ABCDE"       # self-describing length field wrong
    rdata_payload = struct.pack("!H", 1) + target + param(5, bad_ech)  # key 5 = ECH
    qname = dns.name.from_text("example.com.")
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = qname.to_wire() + struct.pack("!HH", 65, 1)
    answer_rr = qname.to_wire() + struct.pack("!HHIH", 65, 1, 300, len(rdata_payload)) + rdata_payload
    return header + question + answer_rr


def selftest():
    failures = []

    def check(label, got, expected):
        ok = got == expected
        print(f"  [{'OK' if ok else 'FAIL'}] {label}: got={got!r} expected={expected!r}")
        if not ok:
            failures.append(label)

    check("no HTTPS params at all (defensive empty case)",
          classify_https_answer(_FakeAnswer([]))["status"], "https_no_ech")

    r1 = classify_https_answer(_FakeAnswer([_rdata('1 svc.example. alpn="h2,h3" port="443"')]))
    check("ServiceForm, no ECH param", r1["status"], "https_no_ech")

    # A syntactically valid ECHConfigList per dnspython's check (first 2 bytes, big-endian,
    # equal len(rest)): content bytes are arbitrary filler, only the self-describing length
    # prefix needs to be correct for this test.
    _valid_ech = "ABQAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

    r2 = classify_https_answer(_FakeAnswer([_rdata(f'1 svc.example. ech="{_valid_ech}"')]))
    check("ServiceForm with valid ECH param", r2["status"], "ech_present")

    r3 = classify_https_answer(_FakeAnswer([_rdata("0 . ")]))
    check("AliasForm only (priority 0)", r3["status"], "alias_form")

    r4 = classify_https_answer(_FakeAnswer([
        _rdata('1 a.example. alpn="h2"'),
        _rdata(f'2 b.example. ech="{_valid_ech}"'),
    ]))
    check("multiple ServiceForm records, ECH on one of them", r4["status"], "ech_present")

    try:
        wire = _build_malformed_ech_wire_message()
        dns.message.from_wire(wire)
        check("malformed ECH length prefix raises on wire parse", "no exception raised", "FormError")
    except dns.exception.FormError as e:
        check("malformed ECH length prefix raises on wire parse (FormError, 'ECHConfigList' in msg)",
              ("FormError", "ECHConfigList" in str(e)), ("FormError", True))
    except Exception as e:
        check("malformed ECH length prefix raises on wire parse", type(e).__name__, "FormError")

    zone_checks = [
        ("www.buet.ac.bd", "buet.ac.bd"),
        ("portal.gov.bd", "portal.gov.bd"),  # 3 labels, "gov.bd" is a known suffix -> keep all 3
        ("a.b.company.bd", "company.bd"),
        ("bare.bd", "bare.bd"),
        ("sub.sub2.ulab.edu.bd", "ulab.edu.bd"),
    ]
    for name, expected in zone_checks:
        check(f"registered_domain({name!r})", registered_domain(name), expected)

    if failures:
        print(f"\nSELFTEST FAILED: {len(failures)} check(s) did not match.")
        return 1
    print(f"\nSELFTEST PASSED: {len(zone_checks) + 6} checks, no network access used.")
    return 0


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def load_resolving_population(liveness_path):
    rows = []
    with open(liveness_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["dns_status"] == "resolves":
                rows.append(row)
    return rows


def load_zone_dnssec(zones_path):
    """registered_domain -> c3's per-zone DNSSEC status, for the cross-tab. Returns {} and
    prints a warning (never raises) if the file isn't found -- that part of the report is
    then skipped rather than guessed at."""
    if not zones_path or not os.path.exists(zones_path):
        print(f"NOTE: zone DNSSEC file not found ({zones_path}) -- skipping the "
              f"ECH-vs-DNSSEC-signed cross-tab in the report.")
        return {}
    out = {}
    with open(zones_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            out[row["registered_domain"]] = row["status"]
    return out


def pct(n, d):
    return f"{100.0 * n / d:.1f}%" if d else "n/a"


MAIN_STATUSES = ["ech_present", "https_no_ech", "alias_form", "no_https_record", "ech_parse_error"]
# Everything that is NOT a conclusive answer about ECH/HTTPS presence -- query-level failures
# (nxdomain/servfail/timeout/error) or an unscanned domain. Folded into one "other / inconclusive"
# column in the per-group breakdowns so every row's counts sum exactly to N -- a row that silently
# summed to less than N (as an earlier version of this table did) is indistinguishable from a bug
# without re-deriving the gap by hand, which is exactly the kind of thing Standing Rule 9 exists
# to prevent: every domain's fate must be visible somewhere in the row, not an implicit remainder.
OTHER_STATUSES = ["nxdomain", "servfail", "timeout", "error", "not_scanned"]


def breakdown_table(recs, group_key, label):
    groups = defaultdict(list)
    for r in recs:
        groups[r[group_key]].append(r)
    lines = [f"| {label} | N | ECH present | % | HTTPS, no ECH | % | Alias-only | % | No HTTPS record | % "
             f"| Parse error | % | Other/inconclusive | % |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for key in sorted(groups):
        rs = groups[key]
        n = len(rs)
        c = Counter(r["https_status"] for r in rs)
        other = sum(c[s] for s in OTHER_STATUSES)
        lines.append(
            f"| {key} | {n} | {c['ech_present']} | {pct(c['ech_present'], n)} "
            f"| {c['https_no_ech']} | {pct(c['https_no_ech'], n)} "
            f"| {c['alias_form']} | {pct(c['alias_form'], n)} "
            f"| {c['no_https_record']} | {pct(c['no_https_record'], n)} "
            f"| {c['ech_parse_error']} | {pct(c['ech_parse_error'], n)} "
            f"| {other} | {pct(other, n)} |"
        )
        assert sum(c[s] for s in MAIN_STATUSES) + other == n, \
            f"row for {key!r} does not sum to N -- a status is falling through unaccounted"
    return "\n".join(lines)


def write_report(recs, zone_dnssec, out_dir):
    n = len(recs)
    overall = Counter(r["https_status"] for r in recs)
    other_statuses = {k: v for k, v in overall.items()
                       if k not in {"ech_present", "https_no_ech", "alias_form",
                                    "no_https_record", "ech_parse_error"}}

    # Zone-level (registered-domain) rollup: a zone counts as ECH-adopted if ANY
    # of its scanned hostnames returned ech_present.
    zone_recs = defaultdict(list)
    for r in recs:
        zone_recs[r["zone"]].append(r)
    zone_ech = {z: any(rr["https_status"] == "ech_present" for rr in rs) for z, rs in zone_recs.items()}
    n_zones = len(zone_recs)
    n_zones_ech = sum(zone_ech.values())

    lines = []
    lines.append("# E2b: ECH adoption via DNS HTTPS records\n")
    lines.append("(PLAN.md Section 4.17 / Section 7 Group 1 item 7)\n")
    lines.append("## Question\n")
    lines.append("Among domains that resolve at all, how many publish a DNS HTTPS record "
                  "(RFC 9460) advertising an ECH SvcParam? How does that relate to the "
                  "already-measured DNSSEC-unsigned rate (Section 4.13)?\n")
    lines.append("## Sample\n")
    lines.append(f"- Population: {n} domains with `dns_status == \"resolves\"` "
                  f"(`data/measurement/processed/liveness_all.csv`)\n")
    lines.append("## Headline result (domain-level)\n")
    lines.append(f"- ECH present: {overall['ech_present']}/{n} ({pct(overall['ech_present'], n)})")
    lines.append(f"- HTTPS record present, no ECH: {overall['https_no_ech']}/{n} ({pct(overall['https_no_ech'], n)})")
    lines.append(f"- AliasForm only (ECH, if any, lives at the alias target -- not followed, see module docstring): "
                 f"{overall['alias_form']}/{n} ({pct(overall['alias_form'], n)})")
    lines.append(f"- No HTTPS record at all: {overall['no_https_record']}/{n} ({pct(overall['no_https_record'], n)})")
    lines.append(f"- ECH parse error (record present, dnspython could not parse its ECH param -- "
                 f"see module docstring METHOD NOTE): {overall['ech_parse_error']}/{n} ({pct(overall['ech_parse_error'], n)})")
    for k, v in sorted(other_statuses.items()):
        lines.append(f"- {k}: {v}/{n} ({pct(v, n)})")
    lines.append("")
    lines.append("## Headline result (zone-level, registered-domain)\n")
    lines.append(f"- Zones with >=1 scanned hostname showing ECH present: {n_zones_ech}/{n_zones} ({pct(n_zones_ech, n_zones)})")
    lines.append("- Zone grouping: registered-domain proxy suffixes ac.bd/co.bd/com.bd/edu.bd/gov.bd/"
                 "info.bd/mil.bd/net.bd/org.bd/sw.bd/tv.bd, reimplementing c3_dnssec_summary.py's "
                 "documented rule -- see module docstring for how this was validated against "
                 "phase_c3_zones.csv (0 mismatches across 1,834 zones).\n")
    lines.append("## By sector\n")
    lines.append(breakdown_table(recs, "category", "Sector"))
    lines.append("")
    lines.append("## By verification tier\n")
    lines.append(breakdown_table(recs, "tier", "Tier"))
    lines.append("")

    if zone_dnssec:
        # phase_c3_zones.csv's actual status values are "unsigned", "signed_no_chain", and
        # "validated" (confirmed directly from the user's own uploaded file, not assumed) --
        # NOT "signed". Caught during this script's own offline pipeline test, where a wrong
        # guess here silently dropped the "validated" zones from the signed-zone count.
        signed_zones = {z for z, s in zone_dnssec.items() if s in ("validated", "signed_no_chain")}
        unsigned_zones = {z for z, s in zone_dnssec.items() if s == "unsigned"}
        matched_signed = [z for z in zone_recs if z in signed_zones]
        matched_unsigned = [z for z in zone_recs if z in unsigned_zones]
        s_ech = sum(zone_ech[z] for z in matched_signed)
        u_ech = sum(zone_ech[z] for z in matched_unsigned)
        lines.append("## ECH adoption vs. DNSSEC signing status (zone-level cross-tab)\n")
        lines.append("Joined against `phase_c3_zones.csv`'s per-zone DNSSEC status "
                     "(Section 4.13: 96.1% of zones unsigned corpus-wide).\n")
        lines.append("| Zone DNSSEC status | Zones | Zones with ECH present | % |")
        lines.append("|---|---|---|---|")
        lines.append(f"| Signed (validated + signed_no_chain) | {len(matched_signed)} | {s_ech} | {pct(s_ech, len(matched_signed))} |")
        lines.append(f"| Unsigned | {len(matched_unsigned)} | {u_ech} | {pct(u_ech, len(matched_unsigned))} |")
        lines.append("")
        lines.append("_Both ECH and DNSSEC are deployment-maturity signals on the DNS side of the "
                     "stack; this cross-tab is descriptive, not a claim that one causes the other -- "
                     "consistent with how the project has treated every other co-occurrence finding "
                     "(e.g. E2a's interpretation notes)._\n")
    else:
        lines.append("## ECH adoption vs. DNSSEC signing status\n")
        lines.append("_Skipped: `phase_c3_zones.csv` was not found at the path given to `--zones`. "
                     "Pass `--zones path/to/phase_c3_zones.csv` to include this cross-tab.\n_")

    lines.append("## Caveats\n")
    lines.append("- This measures ECH presence on the corpus hostname as queried, not the zone as a "
                 "whole; a zone could have ECH on a different hostname than the one scanned here "
                 "(see CAVEAT in the module docstring). Zone-level numbers above are a lower bound.")
    lines.append("- AliasForm hostnames are not followed to their target; any ECH at the alias "
                 "target is not counted here.")
    lines.append("- `ech_parse_error` domains are excluded from both the \"ECH present\" and \"no ECH\" "
                 "counts above by construction -- they are neither, per Standing Rule 9.")

    report = "\n".join(lines) + "\n"
    with open(os.path.join(out_dir, "phase_e2b_report.md"), "w", encoding="utf-8") as f:
        f.write(report)

    def write_breakdown_csv(path, group_key):
        cols = MAIN_STATUSES + OTHER_STATUSES
        groups = defaultdict(list)
        for r in recs:
            groups[r[group_key]].append(r)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow([group_key, "n"] + cols)
            for key in sorted(groups):
                rs = groups[key]
                c = Counter(rr["https_status"] for rr in rs)
                row_vals = [c[s] for s in cols]
                assert sum(row_vals) == len(rs), \
                    f"{path}: row for {key!r} does not sum to N -- a status is falling through unaccounted"
                w.writerow([key, len(rs)] + row_vals)

    write_breakdown_csv(os.path.join(out_dir, "phase_e2b_by_category.csv"), "category")
    write_breakdown_csv(os.path.join(out_dir, "phase_e2b_by_tier.csv"), "tier")

    print(f"Wrote: {out_dir}/phase_e2b_report.md, phase_e2b_by_category.csv, phase_e2b_by_tier.csv")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true", help="run the offline classifier self-test and exit (no network)")
    ap.add_argument("--liveness", help="path to liveness_all.csv (default: data/measurement/processed/liveness_all.csv)")
    ap.add_argument("--zones", help="path to phase_c3_zones.csv, for the ECH-vs-DNSSEC cross-tab (optional)")
    ap.add_argument("--run-id", help="run folder name (default: run_<today>)")
    ap.add_argument("--limit", type=int, help="only the first N resolving domains (smoke test)")
    ap.add_argument("--config", help="alternate config.yaml")
    ap.add_argument("--out-dir", help="where to write phase_e2b_report.md etc. (default: results/tables next to project root)")
    ap.add_argument("--retry-statuses", help="comma-separated status values to re-query even though "
                     "they're already recorded in the raw JSONL (e.g. 'servfail' or 'servfail,timeout'). "
                     "Use this after a suspected transient resolver outage/rate-limit mid-run, instead of "
                     "re-scanning everything: it re-queries only domains whose LAST recorded status is in "
                     "this list, appends the new result (the newer record wins when the report is built), "
                     "and leaves every other domain's result untouched.")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    cfg = load_config(args.config)
    dcfg = cfg["dns"]
    liveness_path = args.liveness or os.path.join(PROCESSED_DIR, "liveness_all.csv")
    if not os.path.exists(liveness_path):
        sys.exit(f"ERROR: liveness file not found: {liveness_path} (run a3_build_live_list.py first, "
                  f"or pass --liveness)")

    population = load_resolving_population(liveness_path)
    if args.limit:
        population = population[: args.limit]
    domains = [r["domain"] for r in population]
    meta_by_domain = {r["domain"]: r for r in population}

    run_id = args.run_id or f"run_{datetime.date.today().isoformat()}"
    run_dir = resolve_run_dir(run_id, create=True)
    out_path = os.path.join(run_dir, "raw", "https_ech.jsonl")

    done = done_keys(out_path)
    retry_statuses = {s.strip() for s in args.retry_statuses.split(",")} if args.retry_statuses else set()
    if retry_statuses:
        # Last recorded status per domain wins (JsonlWriter only appends, so an earlier scan and a
        # later retry of the same domain can both be in the file -- take the most recent one).
        last_status = {}
        for rec in read_jsonl(out_path):
            last_status[rec["domain"]] = rec.get("status")
        stale = {d for d, s in last_status.items() if s in retry_statuses}
        done = done - stale
        print(f"--retry-statuses {sorted(retry_statuses)}: re-queuing {len(stale)} domains "
              f"currently recorded with one of those statuses.")
    todo = [d for d in domains if d not in done]
    print(f"Liveness file: {liveness_path}\nRun: {run_id}\n"
          f"Resolving population: {len(domains)} | already done {len(done)} | to do {len(todo)}")

    update_run_meta(run_dir, "environment_e2b", {"python": platform.python_version(),
                                                  "dnspython": dns.version.version,
                                                  "os": platform.platform()})
    update_run_meta(run_dir, "https_ech", {"config": dcfg, "started": utc_now()})

    writer, limiter = JsonlWriter(out_path), RateLimiter(dcfg["max_qps"])
    counts = Counter()
    try:
        with ThreadPoolExecutor(max_workers=dcfg["workers"]) as pool:
            futures = [pool.submit(resolve_https, d, dcfg, limiter) for d in todo]
            for i, fut in enumerate(as_completed(futures), 1):
                rec = fut.result()
                writer.write(rec)
                counts[rec["status"]] += 1
                if i % 500 == 0 or i == len(todo):
                    print(f"  {i}/{len(todo)}  " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    except KeyboardInterrupt:
        print("\nInterrupted -- progress is saved; re-run the same command to resume.")
        sys.exit(1)
    finally:
        writer.close()

    update_run_meta(run_dir, "https_ech", {"config": dcfg, "finished": utc_now(), "scanned_this_session": len(todo)})
    print(f"Done scanning. Raw output: {out_path}")

    # Build the analysis-ready record set (this run's output, joined with sector/tier/zone).
    all_recs = {}
    with open(out_path, encoding="utf-8") as f:
        import json
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            all_recs[rec["domain"]] = rec

    recs = []
    for d in domains:
        meta = meta_by_domain[d]
        r = all_recs.get(d)
        recs.append({
            "domain": d, "category": meta["category"], "tier": meta["tier"],
            "zone": registered_domain(d),
            "https_status": r["status"] if r else "not_scanned",
        })
    n_not_scanned = sum(1 for r in recs if r["https_status"] == "not_scanned")
    if n_not_scanned:
        print(f"WARNING: {n_not_scanned} domains in the population have no scan result "
              f"(run incomplete) -- report below is over what was actually scanned.")

    zones_path = args.zones or os.path.join(PROCESSED_DIR, "phase_c3_zones.csv")
    zone_dnssec = load_zone_dnssec(zones_path)

    out_dir = args.out_dir or os.path.join(PROCESSED_DIR, "..", "..", "..", "results", "tables")
    out_dir = os.path.normpath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    write_report(recs, zone_dnssec, out_dir)


if __name__ == "__main__":
    main()