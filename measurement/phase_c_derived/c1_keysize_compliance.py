#!/usr/bin/env python3
"""
Phase C, step 1: certificate key-size compliance and post-quantum signature check.

No network access: uses the certificates b1 already stored in tls.jsonl, joined with the
sector/tier/IP columns of data/measurement/processed/phase_b_domains.csv (run b3 first).

WHAT IS CLASSIFIED (leaf certificate, plus the weakest key anywhere in the presented chain)
  Security strength in bits, per NIST SP 800-57 Part 1 Rev. 5 (Table 2, final):
      RSA / DSA modulus  < 1024 -> <80 | 1024-2047 -> 80 | 2048-3071 -> 112 | 3072-7679 -> 128
                         7680-15359 -> 192 | >= 15360 -> 256
      EC key size        < 160  -> <80 | 160-223 -> 80  | 224-255 -> 112    | 256-383 -> 128
                         384-511 -> 192 | >= 512 -> 256            (P-521 = 521 bits -> 256)
      Ed25519 -> 128, Ed448 -> 224 (reported in the 192 tier)
  Status today (2026), per SP 800-57 / SP 800-131A Rev. 2 (final):
      below_112   strength < 112: not acceptable for new signatures
      only_112    exactly 112: acceptable only until end of 2030
      128_plus    >= 128: acceptable
  Leaf signed with SHA-1 or MD5: not acceptable for new signatures (SP 800-131A Rev. 2).
  Post-quantum signature: leaf signature OID is ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).

  NIST IR 8547 (INITIAL PUBLIC DRAFT, Nov 2024 -- not final) proposes deprecating all
  quantum-vulnerable signatures (RSA, ECDSA, EdDSA) after 2030 and disallowing them after 2035.
  Every non-PQ certificate is therefore flagged quantum_vulnerable; the paper must describe the
  2030/2035 dates as proposed.

LIMITATIONS
  - Root certificates are usually not sent by servers, so "weakest in chain" covers only the
    certificates actually presented (leaf + intermediates).
  - Only the certificate b1's primary handshake received is analysed (one per domain).

Outputs:
  data/measurement/processed/phase_c1_keys.csv            one row per live domain
  results/tables/phase_c1_by_category.csv, _by_tier.csv   per-domain % and per-server %
  results/tables/phase_c1_report.md

Usage (from project root):
    python measurement/phase_c_derived/c1_keysize_compliance.py --run-id run_2026-09-19
"""

import argparse
import csv
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from measurement.common.io_utils import PROCESSED_DIR, resolve_run_dir
from measurement.phase_b_tls.b3_parse_results import (OUT_TABLES, load_latest, md_table, pct, server_weighted,
                                                      write_csv)

PQ_SIG_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    **{f"2.16.840.1.101.3.4.3.{i}": "SLH-DSA" for i in range(20, 32)},
}
WEAK_HASHES = {"sha1", "md5"}
TIERS = ["<80", "80", "112", "128", "192", "256"]


def strength(key_type, bits):
    """NIST SP 800-57 Pt 1 Rev 5 security strength (bits) as a tier string, or None if unknown."""
    if not key_type or not bits:
        return None
    bits = int(bits)
    if key_type in ("RSA", "DSA"):
        cuts = [(1024, "<80"), (2048, "80"), (3072, "112"), (7680, "128"), (15360, "192")]
    elif key_type == "EC":
        cuts = [(160, "<80"), (224, "80"), (256, "112"), (384, "128"), (512, "192")]
    elif key_type == "Ed25519":
        return "128"
    elif key_type == "Ed448":
        return "192"
    else:
        return None
    for limit, tier in cuts:
        if bits < limit:
            return tier
    return "256"


def status(tier):
    if tier is None:
        return None
    if tier in ("<80", "80"):
        return "below_112"
    return "only_112" if tier == "112" else "128_plus"


def chain_weakest(chain_pem):
    """Weakest strength tier among the presented certificates (None if nothing parsable)."""
    if not chain_pem:
        return None
    import warnings
    from cryptography import x509
    from measurement.phase_b_tls.tls_probe import _key_info
    worst = None
    for pem in chain_pem:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                kt, kb, _ = _key_info(x509.load_pem_x509_certificate(pem.encode()).public_key())
        except Exception:
            continue
        t = strength(kt, kb)
        if t is not None and (worst is None or TIERS.index(t) < TIERS.index(worst)):
            worst = t
    return worst


def classify(domain_row, tls_rec):
    cert = (tls_rec or {}).get("cert") or {}
    out = {k: domain_row[k] for k in ("domain", "category", "tier", "ip", "is_service_hostname")}
    if not cert or not cert.get("key_type"):
        out.update({"has_cert": False})
        return out
    tier = strength(cert.get("key_type"), cert.get("key_bits"))
    oid = cert.get("sig_alg_oid") or ""
    weakest = chain_weakest(cert.get("chain_pem"))
    out.update({
        "has_cert": True, "key_type": cert.get("key_type"), "key_bits": cert.get("key_bits"),
        "key_curve": cert.get("key_curve") or "", "sig_alg": cert.get("sig_alg"), "sig_hash": cert.get("sig_hash") or "",
        "leaf_strength": tier, "leaf_status": status(tier),
        "chain_weakest_strength": weakest, "chain_status": status(weakest),
        "weak_sig_hash": (cert.get("sig_hash") or "").lower() in WEAK_HASHES,
        "pq_signature": PQ_SIG_OIDS.get(oid, ""),
        "quantum_vulnerable": oid not in PQ_SIG_OIDS,
    })
    return out


def has_key(r):
    return r.get("has_cert") and r.get("leaf_status") is not None


METRICS = [
    ("leaf_below_112", has_key, lambda r: r["leaf_status"] == "below_112"),
    ("leaf_only_112", has_key, lambda r: r["leaf_status"] == "only_112"),
    ("leaf_128_plus", has_key, lambda r: r["leaf_status"] == "128_plus"),
    ("chain_below_112", lambda r: r.get("chain_status") is not None, lambda r: r["chain_status"] == "below_112"),
    ("weak_sig_hash", lambda r: bool(r.get("has_cert")), lambda r: r["weak_sig_hash"]),
    ("pq_signature", lambda r: bool(r.get("has_cert")), lambda r: bool(r["pq_signature"])),
    ("key_rsa", has_key, lambda r: r["key_type"] == "RSA"),
    ("key_ec", has_key, lambda r: r["key_type"] in ("EC", "Ed25519", "Ed448")),
]


def summarize(name, rows):
    out = {"group": name, "domains": len(rows), "servers": len({r["ip"] for r in rows}),
           "with_certificate": sum(1 for r in rows if r.get("has_cert"))}
    for m, den, num in METRICS:
        d = [r for r in rows if den(r)]
        n = sum(1 for r in d if num(r))
        out[f"{m}_n"], out[f"{m}_den"] = n, len(d)
        out[f"{m}_dom_pct"] = pct(n, len(d))
        out[f"{m}_srv_pct"], out[f"{m}_srv_den"] = server_weighted(rows, den, num)
    return out


def table(rows, key):
    groups = {}
    for r in rows:
        groups.setdefault(r[key], []).append(r)
    t = [summarize(g, rs) for g, rs in sorted(groups.items(), key=lambda kv: -len(kv[1]))]
    t.append(summarize("ALL", rows))
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
        domains = list(csv.DictReader(f))
    tls, dupes = load_latest(os.path.join(run_dir, "raw", "tls.jsonl"))
    missing = [d["domain"] for d in domains if d["domain"] not in tls]
    if missing:
        sys.exit(f"ERROR: {len(missing)} domains in phase_b_domains.csv have no tls.jsonl record (e.g. {missing[:3]}). "
                 "Re-run b3 for this run.")

    rows = [classify(d, tls[d["domain"]]) for d in domains]
    for r in rows:
        r["is_service_hostname"] = str(r["is_service_hostname"]) == "True"

    by_cat, by_tier = table(rows, "category"), table(rows, "tier")
    web = [r for r in rows if not r["is_service_hostname"]]
    by_cat_x = table(web, "category")

    os.makedirs(OUT_TABLES, exist_ok=True)
    cols = ["domain", "category", "tier", "ip", "is_service_hostname", "has_cert", "key_type", "key_bits", "key_curve",
            "sig_alg", "sig_hash", "leaf_strength", "leaf_status", "chain_weakest_strength", "chain_status",
            "weak_sig_hash", "pq_signature", "quantum_vulnerable"]
    write_csv(os.path.join(PROCESSED_DIR, "phase_c1_keys.csv"), rows, cols)
    write_csv(os.path.join(OUT_TABLES, "phase_c1_by_category.csv"), by_cat)
    write_csv(os.path.join(OUT_TABLES, "phase_c1_by_tier.csv"), by_tier)

    with_cert = [r for r in rows if r.get("has_cert")]
    dist = Counter((r["key_type"], r["leaf_strength"]) for r in with_cert)
    sig = Counter(r["sig_alg"] for r in with_cert)
    labels_m = ["leaf_below_112", "leaf_only_112", "leaf_128_plus", "chain_below_112", "weak_sig_hash", "pq_signature"]
    labels = ["leaf < 112-bit", "leaf = 112-bit (until 2030)", "leaf >= 128-bit", "chain < 112-bit",
              "SHA-1/MD5 signed", "PQ signature"]
    a = by_cat[-1]
    md = "\n".join([
        f"# Phase C1: certificate key strength (`{args.run_id}`)", "",
        f"- Live domains {len(rows)}; with a certificate {a['with_certificate']}. Cells: per-domain % / per-server %.",
        "- Strength tiers: NIST SP 800-57 Pt 1 Rev 5. `< 112` not acceptable for new signatures; `112` acceptable until 2030.",
        "- NIST IR 8547 (draft, not final) proposes deprecating all RSA/ECC signatures after 2030 and disallowing them after 2035.",
        f"- Duplicate tls records resolved by latest timestamp: {dupes}.", "",
        "## By sector", "", md_table(by_cat, labels_m, labels), "",
        "## By verification tier", "", md_table(by_tier, labels_m, labels), "",
        f"## Excluding service hostnames ({len(rows) - len(web)} removed)", "", md_table(by_cat_x, labels_m, labels), "",
        "## Leaf key type x strength (domain counts)", "", "| key type | strength (bits) | domains |", "|---|---|---|",
    ] + [f"| {k} | {t} | {n} |" for (k, t), n in sorted(dist.items(), key=lambda kv: -kv[1])] + [
        "", "## Leaf signature algorithms (domain counts)", "", "| algorithm | domains |", "|---|---|",
    ] + [f"| {k} | {n} |" for k, n in sig.most_common()] + [""])
    with open(os.path.join(OUT_TABLES, "phase_c1_report.md"), "w", encoding="utf-8") as f:
        f.write(md)

    print(f"Run: {args.run_id} | live domains {len(rows)} | with certificate {a['with_certificate']}")
    for m, lab in zip(labels_m, labels):
        print(f"  {lab:28s} {a[m + '_n']:5d}/{a[m + '_den']:<5d} dom {a[m + '_dom_pct']}%  srv {a[m + '_srv_pct']}%")
    print("  leaf key types:", dict(Counter(r["key_type"] for r in with_cert)))
    print(f"Wrote: {PROCESSED_DIR}/phase_c1_keys.csv, results/tables/phase_c1_*")


if __name__ == "__main__":
    main()