#!/usr/bin/env python3
"""
Phase C, step 2: legacy cipher / protocol vulnerability inference.

No network access: uses ciphers b1 already negotiated, from two independent connections per
domain (both already in tls.jsonl):
  primary       whatever version/cipher the server preferred (tls_probe.py top-level
                'tls_version'/'cipher' fields) -- used for Sweet32 (a 64-bit block cipher can be
                negotiated at any TLS version, including 1.2/1.3 if a server still offers one).
  old_versions  a SEPARATE handshake offering ONLY TLS 1.0-1.1 (tls_probe.py's independent probe,
                run for every domain regardless of the server's best version) -- used for
                Lucky13/BEAST, since those need a CBC cipher specifically on TLS 1.0/1.1.
Confirmed before writing this script: probes.old_versions.cipher holds real OpenSSL cipher names
(e.g. 'ECDHE-RSA-AES256-SHA') on the TLS 1.0/1.1-only connection, not just a version.

WHAT IS MEASURED, AND HOW
  Lucky13 / BEAST (CBC-mode cipher on TLS 1.0/1.1)   MEASURED from tls.jsonl (old_versions cipher), BUT
                                                       READ THIS BEFORE QUOTING THE NUMBER: under TLS
                                                       1.0/1.1, AEAD ciphers (GCM, ChaCha20) are not a
                                                       protocol option at all (RFC 5289 defines them for
                                                       TLS 1.2 only), and the bundled scanner has RC4
                                                       compiled out (see Sweet32 note below). So EVERY
                                                       cipher this tool can possibly offer at TLS 1.0/1.1
                                                       is CBC-mode. A successful old_versions handshake is
                                                       therefore CBC by construction, not by server choice
                                                       -- lucky13_beast_exposed will read at or near 100%
                                                       for any domain that accepts old TLS, regardless of
                                                       that server's real cipher preferences. This is a
                                                       measurement of "accepts TLS 1.0/1.1 at all"
                                                       (already reported directly by b3's
                                                       accepts_tls_1_0_or_1_1), not independent evidence
                                                       of a CBC preference. Report accepts_tls_1_0_or_1_1
                                                       as the finding; do not present the ~100% CBC rate
                                                       as if it were measured server behaviour.
  POODLE (SSLv3 + CBC)                               MEASURED by c2b, NOT from tls.jsonl: b1's
                                                       library has no SSLv3. c2b probes SSLv3 with a
                                                       private OpenSSL 1.1.1w build (legacy_probe.py),
                                                       once per IP (SSLv3 carries no hostname), and
                                                       marks a server POODLE-exposed when it accepts
                                                       SSLv3 with a CBC cipher.
  3DES / Sweet32-class (64-bit block cipher)         MEASURED by c2b (per domain, with SNI):
                                                       "accepts 3DES when offered". The bundled OpenSSL
                                                       has 3DES/DES/RC2/RC4 compiled OUT, so tls.jsonl
                                                       cannot show it (a 0% there would be meaningless).
                                                       Not the same as "Sweet32-vulnerable": modern
                                                       clients no longer offer 3DES.
  If c2b has not been run, the SSLv3/3DES columns are empty and the report says "not tested";
  a missing measurement is never reported as "0 vulnerable".
  idea_negotiated is kept as the one Sweet32-class cipher the bundled OpenSSL can still see.
  Heartbleed                                          OUT OF SCOPE by project rule (active
                                                       exploitation: it extracts server memory).
  POODLE over TLS                                     NOT TESTED (needs records with corrupted padding).

CIPHER NAME MATCHING
  OpenSSL cipher-suite names encode the algorithm directly (e.g. 'DES-CBC3-SHA' = 3DES-CBC,
  'ECDHE-RSA-AES128-SHA' = AES-128-CBC, 'ECDHE-RSA-AES128-GCM-SHA256' = AES-128-GCM). Matching is
  done on these name fragments -- documented, checkable against the raw string, not a black box.
  '-CBC' is implicit in classic (non-GCM/non-CHACHA) TLS 1.0-1.2 suites; OpenSSL does not always
  print the literal substring "CBC" for every one of them, so a cipher counts as CBC-mode if it
  names a CBC-only cipher (3DES/DES/IDEA/SEED/RC2) or an AES/CAMELLIA suite with no AEAD marker
  (no GCM, CCM, CHACHA20, or the '-SHA256'-only-AEAD exceptions do not exist in this list).

Outputs:
  data/measurement/processed/phase_c2_ciphers.csv           one row per live domain
  results/tables/phase_c2_by_category.csv, _by_tier.csv
  results/tables/phase_c2_report.md

Usage (from project root):
    python measurement/phase_c_derived/c2_legacy_cipher_inference.py --run-id run_2026-09-19
"""

import argparse
import csv
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import PROCESSED_DIR, read_jsonl, resolve_run_dir
from measurement.phase_b_tls.b3_parse_results import (OUT_TABLES, load_latest, md_table, pct, server_weighted,
                                                      write_csv)

# IDEA is the only Sweet32-class (64-bit block) cipher this build can even negotiate (checked
# directly: 3DES/DES/RC2/RC4 are compiled out of the bundled OpenSSL -- see module docstring).
IDEA_RE = re.compile(r"IDEA", re.I)
AEAD_RE = re.compile(r"GCM|CCM|CHACHA20|POLY1305", re.I)
STREAM_OR_KEYLESS_RE = re.compile(r"RC4|NULL", re.I)
CBC_CAPABLE_RE = re.compile(r"AES|CAMELLIA|SEED|DES|IDEA", re.I)


def is_cbc_mode(cipher):
    """True for a classic CBC-mode suite; False for AEAD (GCM/CCM/ChaCha), RC4, or NULL."""
    if not cipher:
        return None
    if AEAD_RE.search(cipher) or STREAM_OR_KEYLESS_RE.search(cipher):
        return False
    return bool(CBC_CAPABLE_RE.search(cipher))


def classify(row, legacy_ip=None, legacy_des=None):
    d, ip, cat, tier = row["domain"], row["ip"], row["category"], row["tier"]
    out = {"domain": d, "category": cat, "tier": tier, "ip": ip, "is_service_hostname": row["is_service_hostname"]}

    primary_cipher = row.get("cipher") or None
    ov = (row.get("probes") or {}).get("old_versions") or {}
    ov_ok = ov.get("status") == "ok"
    ov_cipher, ov_version = (ov.get("cipher"), ov.get("tls_version")) if ov_ok else (None, None)

    out["primary_cipher"] = primary_cipher
    out["primary_tls_version"] = row.get("tls_version")
    out["old_version_cipher"] = ov_cipher
    out["old_version_tls_version"] = ov_version

    out["idea_negotiated"] = bool((primary_cipher and IDEA_RE.search(primary_cipher)) or
                                  (ov_cipher and IDEA_RE.search(ov_cipher)))
    cbc_old = is_cbc_mode(ov_cipher)
    out["lucky13_beast_exposed"] = bool(cbc_old) if ov_cipher else None

    # c2b results (empty unless c2b_legacy_scan.py has been run). SSLv3 is per IP: it has no SNI.
    li, ld = legacy_ip or {}, legacy_des or {}
    out["accepts_sslv3"] = li.get("accepts_sslv3")
    out["poodle_exposed"] = li.get("poodle_exposed")
    out["sslv3_cipher"] = (li.get("offer_all") or {}).get("cipher")
    out["accepts_3des"] = ld.get("accepts_3des")
    out["des3_protocol"] = ld.get("protocol")
    out["des3_cipher"] = ld.get("cipher")
    out["poodle_tested"] = out["accepts_sslv3"] is not None
    out["des3_probed"] = out["accepts_3des"] is not None
    return out


def has_primary_cipher(r):
    return bool(r["primary_cipher"])


def has_old_cipher(r):
    return bool(r["old_version_cipher"])


def has_either(r):
    return bool(r["primary_cipher"] or r["old_version_cipher"])


METRICS = [
    ("lucky13_beast_exposed", has_old_cipher, lambda r: r["lucky13_beast_exposed"] is True),
    ("idea_negotiated", has_either, lambda r: r["idea_negotiated"] is True),
]
LEGACY_METRICS = [       # only when c2b has produced data; inconclusive results are excluded, never "no"
    ("accepts_sslv3", lambda r: r["accepts_sslv3"] is not None, lambda r: r["accepts_sslv3"] is True),
    ("poodle_exposed", lambda r: r["poodle_exposed"] is not None, lambda r: r["poodle_exposed"] is True),
    ("accepts_3des", lambda r: r["accepts_3des"] is not None, lambda r: r["accepts_3des"] is True),
]


def summarize(name, rows, metrics=METRICS):
    out = {"group": name, "domains": len(rows), "servers": len({r["ip"] for r in rows}),
           "with_old_version_cipher": sum(1 for r in rows if r["old_version_cipher"])}
    for m, den, num in metrics:
        d = [r for r in rows if den(r)]
        n = sum(1 for r in d if num(r))
        out[f"{m}_n"], out[f"{m}_den"] = n, len(d)
        out[f"{m}_dom_pct"] = pct(n, len(d))
        out[f"{m}_srv_pct"], out[f"{m}_srv_den"] = server_weighted(rows, den, num)
    return out


def table(rows, key, metrics=METRICS):
    groups = {}
    for r in rows:
        groups.setdefault(r[key], []).append(r)
    t = [summarize(g, rs, metrics) for g, rs in sorted(groups.items(), key=lambda kv: -len(kv[1]))]
    t.append(summarize("ALL", rows, metrics))
    return t


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()

    run_dir = resolve_run_dir(args.run_id)
    dom_path = os.path.join(PROCESSED_DIR, "phase_b_domains.csv")
    if not os.path.exists(dom_path):
        sys.exit(f"ERROR: {dom_path} not found -- run b3_parse_results.py --run-id {args.run_id} first.")
    with open(dom_path, newline="", encoding="utf-8") as f:
        domains = {r["domain"]: r for r in csv.DictReader(f)}
    tls, dupes = load_latest(os.path.join(run_dir, "raw", "tls.jsonl"))
    missing = [d for d in domains if d not in tls]
    if missing:
        sys.exit(f"ERROR: {len(missing)} domains in phase_b_domains.csv have no tls.jsonl record "
                 f"(e.g. {missing[:3]}). Re-run b3 for this run.")

    legacy_ip = {r["ip"]: r for r in read_jsonl(os.path.join(run_dir, "raw", "legacy_sslv3_ip.jsonl"))}
    legacy_des = {r["domain"]: r for r in read_jsonl(os.path.join(run_dir, "raw", "legacy_3des.jsonl"))}
    have_legacy = bool(legacy_ip or legacy_des)

    rows = []
    for d, dom_row in domains.items():
        t = tls[d]
        rows.append(classify({"domain": d, "ip": dom_row["ip"], "category": dom_row["category"],
                              "tier": dom_row["tier"], "is_service_hostname": dom_row["is_service_hostname"],
                              "cipher": t.get("cipher"), "tls_version": t.get("tls_version"),
                              "probes": t.get("probes")}, legacy_ip.get(dom_row["ip"]), legacy_des.get(d)))

    metrics = METRICS + (LEGACY_METRICS if have_legacy else [])
    by_cat, by_tier = table(rows, "category", metrics), table(rows, "tier", metrics)
    web = [r for r in rows if str(r["is_service_hostname"]) != "True"]
    by_cat_x = table(web, "category", metrics)

    os.makedirs(OUT_TABLES, exist_ok=True)
    cols = ["domain", "category", "tier", "ip", "is_service_hostname", "primary_cipher", "primary_tls_version",
            "old_version_cipher", "old_version_tls_version", "lucky13_beast_exposed", "idea_negotiated",
            "accepts_sslv3", "poodle_exposed", "sslv3_cipher", "accepts_3des", "des3_protocol", "des3_cipher",
            "poodle_tested", "des3_probed"]
    write_csv(os.path.join(PROCESSED_DIR, "phase_c2_ciphers.csv"), rows, cols)
    write_csv(os.path.join(OUT_TABLES, "phase_c2_by_category.csv"), by_cat)
    write_csv(os.path.join(OUT_TABLES, "phase_c2_by_tier.csv"), by_tier)

    cipher_freq = Counter(r["primary_cipher"] for r in rows if r["primary_cipher"])
    old_cipher_freq = Counter(r["old_version_cipher"] for r in rows if r["old_version_cipher"])
    labels_m = [m for m, _, _ in metrics]
    label_of = {"lucky13_beast_exposed": "Lucky13/BEAST (near-100% by construction -- see note)",
                "idea_negotiated": "IDEA negotiated (only Sweet32-class cipher the main scanner can see)",
                "accepts_sslv3": "Accepts SSLv3 (per IP)", "poodle_exposed": "POODLE-exposed (SSLv3 + CBC)",
                "accepts_3des": "Accepts 3DES when offered"}
    labels = [label_of[m] for m in labels_m]
    a = by_cat[-1]
    n_ssl = sum(1 for r in rows if r["accepts_sslv3"] is not None)
    n_des = sum(1 for r in rows if r["accepts_3des"] is not None)
    lucky13_note = [
        "- **The Lucky13/BEAST rate is structurally near-100% and is NOT an independent server-behaviour "
        "finding.** AEAD ciphers (GCM, ChaCha20) are only defined for TLS 1.2 (RFC 5289), so they are not a "
        "protocol option under TLS 1.0/1.1 at all; the scanner's cipher library also has RC4 compiled out. "
        "Every cipher this tool can offer at TLS 1.0/1.1 is therefore CBC-mode, so any domain that accepts "
        "old TLS necessarily shows as CBC here, regardless of that server's real preferences. The real, "
        "independently meaningful figure is b3's `accepts_tls_1_0_or_1_1` -- cite that, not this rate, as the "
        "finding; use this field only to confirm the mechanism, not as a second data point.",
    ]
    if have_legacy:
        legacy_notes = [
            "- **SSLv3 / POODLE and 3DES were measured by c2b** with a separate OpenSSL 1.1.1w build (the main "
            "scanner cannot offer them). SSLv3 is probed once per IP because it carries no hostname; "
            "3DES once per domain. A server is POODLE-exposed when it accepts SSLv3 with a CBC cipher. "
            "3DES is reported as *accepts 3DES when offered*, not as 'Sweet32-vulnerable'.",
            f"- Coverage: SSLv3 answered for {n_ssl} of {len(rows)} domains, 3DES for {n_des}; the rest were "
            "inconclusive or deferred (unreachable at scan time) and are excluded from denominators, not counted as 'no'.",
            "- **POODLE over TLS** (broken TLS padding checks) was not tested: it needs records with corrupted padding.",
        ]
    else:
        legacy_notes = [
            "- **SSLv3/POODLE and 3DES were not tested** (c2b has not been run): the main scanner's library has "
            "no SSLv3 and no 3DES, so no result exists. Not reported as '0 vulnerable'.",
        ]
    md = "\n".join([
        f"# Phase C2: legacy cipher / protocol vulnerability inference (`{args.run_id}`)", "",
        f"- Live domains {len(rows)}. Cells: per-domain % / per-server %.",
    ] + lucky13_note + legacy_notes + [
        "- **Heartbleed is out of scope by project rule** (it extracts server memory: active exploitation).",
        f"- Duplicate tls records resolved by latest timestamp: {dupes}.",
        f"- {a['with_old_version_cipher']} of {a['domains']} domains have a cipher from the "
        "independent TLS 1.0/1.1-only probe (the rest never completed that connection).", "",
        "## By sector", "", md_table(by_cat, labels_m, labels), "",
        "## By verification tier", "", md_table(by_tier, labels_m, labels), "",
        f"## Excluding service hostnames ({len(rows) - len(web)} removed)", "", md_table(by_cat_x, labels_m, labels), "",
        "## Most common negotiated ciphers, primary handshake (domain counts)", "",
        "| cipher | domains | IDEA? |", "|---|---|---|",
    ] + [f"| {c} | {n} | {'yes' if IDEA_RE.search(c) else ''} |" for c, n in cipher_freq.most_common(10)] + [
        "", "## Most common ciphers, TLS 1.0/1.1-only probe (domain counts)", "",
        "| cipher | domains | CBC-mode? |", "|---|---|---|",
    ] + [f"| {c} | {n} | {'yes' if is_cbc_mode(c) else 'no'} |"
         for c, n in old_cipher_freq.most_common(10)] + [""])
    with open(os.path.join(OUT_TABLES, "phase_c2_report.md"), "w", encoding="utf-8") as f:
        f.write(md)

    print(f"Run: {args.run_id} | live domains {len(rows)} | with old-version cipher {a['with_old_version_cipher']}")
    for m, lab in zip(labels_m, labels):
        print(f"  {lab:68s} {a[m + '_n']:5d}/{a[m + '_den']:<5d} dom {a[m + '_dom_pct']}%  srv {a[m + '_srv_pct']}%")
    if not have_legacy:
        print("  SSLv3/POODLE and 3DES: not tested (run c2b_legacy_scan.py first)")
    print(f"Wrote: {PROCESSED_DIR}/phase_c2_ciphers.csv, results/tables/phase_c2_*")


if __name__ == "__main__":
    main()