#!/usr/bin/env python3
"""
Phase D, step 2: baseline comparison table against the three reference papers.

Real, runnable replacement for the empty stub at
measurement/phase_d_analysis/d2_baseline_comparison.py.

This study's own figures are COMPUTED here from the real joined data
(data/measurement/processed/phase_d_joined.csv), never hand-typed. The three
reference papers' figures are NOT computed here -- they are external published
numbers, entered as constants with a citation for each, exactly as this
project's own PLAN.md Section 3 and bibliography record them. That split is
deliberate: this script is a comparison table, not a re-measurement of papers
we don't have raw access to.

Input:
  data/measurement/processed/phase_d_joined.csv

Outputs (results/tables/):
  phase_d_baseline_comparison.csv
  phase_d_baseline_comparison_report.md

Sources for the reference figures (full citations in PLAN.md Appendix):
  BASE  = Dubey & Varshney, "Measurement Study of Post-Quantum Readiness of
          Internet: 2026," arXiv:2606.16473 (India-centric, 32,011 domains)
  UK    = Loizou & Ghadafi, "Measuring Post-Quantum TLS Deployment Across UK
          Internet Sectors," arXiv:2608.02147 (4,665 UK orgs)
  GLOBAL= Wickramasinghe, Li, Jha & Shaghaghi, "Mind the Gap: Policy vs Reality
          in Post-Quantum TLS Deployment," arXiv:2607.29005 (1M domains, global)
"""
import argparse
import os
import pandas as pd

INPUT_DEFAULT = "data/measurement/processed/phase_d_joined.csv"
C4_DEFAULT = "data/measurement/processed/phase_c4_domains.csv"
OUT_DIR_DEFAULT = "results/tables"


def is_pq_group(name):
    return isinstance(name, str) and ("MLKEM" in name.upper() or "KYBER" in name.upper())


def smtp_pq_summary(c4_path):
    """Added 2026-10-15 once smtp_probe.py/c4_smtp_scan.py were patched to capture the negotiated
    TLS group over STARTTLS (previously a stated gap -- see PLAN.md Section 4.17/5.3). Returns a
    one-line string with both denominators, since the UK paper's own SMTP figure (6.4%) and the
    HTTPS figure here use different conventions and neither is obviously "the" right one to match."""
    try:
        c4 = pd.read_csv(c4_path)
    except FileNotFoundError:
        return ("NOT COMPUTED -- {} not found. Re-run the patched c4_smtp_scan.py "
                "(see smtp_probe.py's 2026-10-15 patch) to produce it.".format(c4_path))
    if "group" not in c4.columns:
        return (f"NOT COMPUTED -- {c4_path} has no `group` column yet. "
                "Re-run c4_smtp_scan.py with the patched smtp_probe.py.")
    ok = c4[c4["status"] == "ok"]
    pq_n = ok["group"].apply(is_pq_group).sum()
    return (f"{pct(pq_n, len(ok))} ({pq_n}/{len(ok)} of completed STARTTLS handshakes) / "
            f"{pct(pq_n, len(c4))} ({pq_n}/{len(c4)} of all domains with a usable MX record)")

# --- external reference figures (not computed here; see module docstring) ---
REFERENCE_ROWS = [
    {"metric": "TLS 1.3 adoption",
     "this_study": None,  # filled in from real data below
     "base_paper": "52.41%", "uk_paper": "n/r", "global_paper": "n/r"},
    {"metric": "Hybrid PQ key-exchange adoption",
     "this_study": None,
     "base_paper": "49.3%", "uk_paper": "44.0% (HTTPS) / 6.4% (SMTP)", "global_paper": "n/r"},
    {"metric": "PQ certificate signatures in use",
     "this_study": None,
     "base_paper": "0%", "uk_paper": "n/r", "global_paper": "n/r"},
    {"metric": "Share of PQ adopters using X25519MLKEM768",
     "this_study": None,
     "base_paper": "n/r", "uk_paper": "n/r",
     "global_paper": "~universal convergence on X25519MLKEM768 (described, not a single %)"},
    {"metric": "Fraction of PQ adoption attributable to infrastructure provider",
     "this_study": "descriptive only -- see phase_d_provider_breakdown.csv; "
                    "no regression run (Group 3 of PLAN.md Section 7, deliberately not replicated)",
     "base_paper": "n/r", "uk_paper": "provider AUC 0.957-0.994 vs sector AUC 0.156-0.573 (regression)",
     "global_paper": "93.92%"},
    {"metric": "DNSSEC chain validation",
     "this_study": None,
     "base_paper": "n/r (not measured)", "uk_paper": "n/r (not measured)", "global_paper": "n/r (not measured)"},
    {"metric": "Legacy-protocol / cipher exposure (SSLv3, POODLE, 3DES, etc.)",
     "this_study": None,
     "base_paper": "n/r", "uk_paper": "n/r",
     "global_paper": "measured via cipher-suite inspection (POODLE/SWEET32/FREAK/BEAST/Lucky13/RC4/LOGJAM/BREACH); no single summary % given"},
]
# "n/r" = not reported by that paper / not directly comparable (different methodology or not measured)


def pct(n, d):
    return f"{round(100 * n / d, 1)}%" if d else "n/a"


def compute_this_study(df, c4_path=C4_DEFAULT):
    out = {}

    hs_ok = df["tls_status"] == "ok"
    tls13_n = (df.loc[hs_ok, "tls_version"] == "TLSv1.3").sum()
    out["tls13"] = f"{pct(tls13_n, hs_ok.sum())} ({tls13_n}/{hs_ok.sum()} of completed handshakes)"

    pq_n = (df["pq_class"] == "pq_default").sum()
    https_pq = f"{pct(pq_n, len(df))} ({pq_n}/{len(df)} live domains)"
    smtp_pq = smtp_pq_summary(c4_path)
    out["pq_default"] = f"HTTPS: {https_pq}; SMTP: {smtp_pq}"   # no literal '|' -- would break the md table

    cert_n = df["c1_has_cert"].fillna(False).astype(bool).sum() if "c1_has_cert" in df else df["cert_trusted"].notna().sum()
    pq_sig_n = df.get("c1_pq_signature", pd.Series(dtype=bool)).fillna(False).astype(bool).sum()
    out["pq_signature"] = f"{pct(pq_sig_n, cert_n)} ({pq_sig_n}/{cert_n} certificates presented)"

    pq_rows = df[df["pq_class"] == "pq_default"]
    x25519_n = (pq_rows["group"] == "X25519MLKEM768").sum()
    out["x25519mlkem768_share"] = f"{pct(x25519_n, len(pq_rows))} ({x25519_n}/{len(pq_rows)} PQ-adopting domains)"

    sslv3_n = df["c2_accepts_sslv3"].fillna(False).astype(bool).sum()
    des3_n = df["c2_accepts_3des"].fillna(False).astype(bool).sum()
    des3_den = df["c2_des3_probed"].fillna(False).astype(bool).sum()
    out["legacy_exposure"] = (f"SSLv3 {pct(sslv3_n, len(df))} ({sslv3_n}/{len(df)} domains), "
                               f"3DES-when-offered {pct(des3_n, des3_den)} ({des3_n}/{des3_den} domains probed)")

    if "c3_registered_domain" in df:
        zone_validated = df.groupby("c3_registered_domain")["c3_ad_validated"].apply(
            lambda s: bool(s.fillna(False).astype(bool).any())
        )
        zones_validated_n = int(zone_validated.sum())
        zones_den = len(zone_validated)
    else:
        zones_validated_n = None
        zones_den = None
    if zones_den:
        out["dnssec"] = f"{pct(zones_validated_n, zones_den)} ({zones_validated_n}/{zones_den} zones, approximate -- see Phase C3)"
    else:
        out["dnssec"] = "n/a -- c3_registered_domain column not found in input"

    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=INPUT_DEFAULT)
    ap.add_argument("--c4-domains", default=C4_DEFAULT,
                    help="per-domain SMTP/STARTTLS results from c4_smtp_scan.py (needs the "
                         "2026-10-15 group-capturing patch; falls back to a stated gap if missing)")
    ap.add_argument("--out-dir", default=OUT_DIR_DEFAULT)
    args = ap.parse_args()

    df = pd.read_csv(args.input, low_memory=False)
    os.makedirs(args.out_dir, exist_ok=True)

    computed = compute_this_study(df, args.c4_domains)
    rows = [dict(r) for r in REFERENCE_ROWS]
    fill_order = ["tls13", "pq_default", "pq_signature", "x25519mlkem768_share",
                  None, "dnssec", "legacy_exposure"]
    for row, key in zip(rows, fill_order):
        if key is not None:
            row["this_study"] = computed[key]

    out_df = pd.DataFrame(rows)
    out_df.to_csv(os.path.join(args.out_dir, "phase_d_baseline_comparison.csv"), index=False)

    lines = [
        f"# Phase D baseline comparison (this study's figures computed from `{args.input}`, "
        f"{len(df)} live domains; reference figures are external, cited in PLAN.md Appendix)",
        "",
        "| metric | this study | base paper (India) | UK paper | global paper |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| {r['metric']} | {r['this_study']} | {r['base_paper']} | {r['uk_paper']} | {r['global_paper']} |")
    lines += [
        "",
        "'n/r' = not reported by that paper, or not directly comparable (different methodology, different metric, or not measured at all).",
        "SMTP figure reads 'of completed STARTTLS handshakes / of all domains with a usable MX record' -- "
        "two different denominators, shown both ways because the UK paper's own 6.4% SMTP figure's exact "
        "denominator convention isn't restated here from memory. This was a stated gap until 2026-10-15, "
        "when smtp_probe.py/c4_smtp_scan.py were patched to capture the negotiated TLS group over STARTTLS "
        "(previously only TLS version/cipher were recorded).",
    ]
    report = "\n".join(lines)
    with open(os.path.join(args.out_dir, "phase_d_baseline_comparison_report.md"), "w", encoding="utf-8") as f:
        f.write(report)
    print(report)


if __name__ == "__main__":
    main()