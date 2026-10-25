#!/usr/bin/env python3
"""
One-off follow-up to d2_baseline_comparison.py's smtp_pq_summary(): splits the
SMTP PQ-adoption figure into Google-hosted mail (aspmx.l.google.com +
smtp.google.com) vs. everything else, to check whether the headline 41.0%/36.7%
figure is mostly a Google-hosting-concentration effect.

No new scanning -- reads the existing phase_c4_domains.csv directly (same file
d2_baseline_comparison.py's smtp_pq_summary() reads). Run from the project root:

    python3 smtp_pq_google_breakdown.py

Or, if phase_c4_domains.csv isn't at the default path:

    python3 smtp_pq_google_breakdown.py --input path/to/phase_c4_domains.csv
"""
import argparse
import pandas as pd

GOOGLE_MX_HOSTS = {"aspmx.l.google.com", "smtp.google.com"}

INPUT_DEFAULT = "data/measurement/processed/phase_c4_domains.csv"


def pct(n, d):
    return round(100 * n / d, 1) if d else None


def pq_summary(df, label):
    """Mirrors d2_baseline_comparison.py's smtp_pq_summary() logic, scoped to
    whatever subset `df` already is."""
    total_domains = len(df)

    completed = df[df["status"] == "ok"]
    completed_n = len(completed)
    pq_of_completed = int((completed["group"] == "X25519MLKEM768").sum())

    pq_of_all = int((df["group"] == "X25519MLKEM768").sum())

    print(f"\n--- {label} ---")
    print(f"domains in group: {total_domains}")
    print(f"completed STARTTLS handshakes: {completed_n}")
    print(
        f"PQ (X25519MLKEM768) of completed handshakes: {pq_of_completed}/{completed_n} "
        f"({pct(pq_of_completed, completed_n)}%)"
    )
    print(
        f"PQ (X25519MLKEM768) of all domains in group: {pq_of_all}/{total_domains} "
        f"({pct(pq_of_all, total_domains)}%)"
    )
    return {
        "label": label,
        "domains": total_domains,
        "completed": completed_n,
        "pq_of_completed_n": pq_of_completed,
        "pq_of_completed_pct": pct(pq_of_completed, completed_n),
        "pq_of_all_n": pq_of_all,
        "pq_of_all_pct": pct(pq_of_all, total_domains),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=INPUT_DEFAULT)
    args = ap.parse_args()

    df = pd.read_csv(args.input, low_memory=False)

    if "mx_host" not in df.columns or "group" not in df.columns:
        raise SystemExit(
            f"Expected columns 'mx_host' and 'group' not both found in {args.input}. "
            f"Columns present: {list(df.columns)}"
        )

    is_google = df["mx_host"].isin(GOOGLE_MX_HOSTS)
    google_df = df[is_google]
    other_df = df[~is_google]

    print(f"Loaded {len(df)} rows from {args.input}")
    print(f"Google-hosted (aspmx.l.google.com + smtp.google.com): {len(google_df)} domains")
    print(f"Everything else: {len(other_df)} domains")

    all_result = pq_summary(df, "ALL (matches d2_baseline_comparison.py's existing figure)")
    google_result = pq_summary(google_df, "GOOGLE-HOSTED MAIL ONLY")
    other_result = pq_summary(other_df, "EVERYTHING ELSE (non-Google mail)")

    print("\n--- Summary table ---")
    print(f"{'group':<12} {'domains':>8} {'completed':>10} {'PQ/completed':>14} {'PQ/all':>10}")
    for r in (all_result, google_result, other_result):
        pq_c = f"{r['pq_of_completed_n']}/{r['completed']} ({r['pq_of_completed_pct']}%)"
        pq_a = f"{r['pq_of_all_n']}/{r['domains']} ({r['pq_of_all_pct']}%)"
        print(f"{r['label'].split()[0]:<12} {r['domains']:>8} {r['completed']:>10} {pq_c:>14} {pq_a:>10}")

    print(
        "\nIf GOOGLE-HOSTED's PQ rate is near 99-100% and EVERYTHING ELSE's rate is much "
        "lower, the 41.0%/36.7% headline figure is largely a Google effect, and the "
        "'narrower HTTPS/SMTP gap vs. the UK paper' claim needs to be reframed around "
        "that (e.g. reported as two numbers -- Google-hosted vs. rest -- rather than one "
        "blended national figure)."
    )


if __name__ == "__main__":
    main()
