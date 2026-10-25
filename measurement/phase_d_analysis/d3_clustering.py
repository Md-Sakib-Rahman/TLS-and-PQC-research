#!/usr/bin/env python3
"""
Phase D, step 3: unsupervised clustering of TLS/PQC configuration profiles.

Real, runnable replacement for the empty stub at
measurement/phase_d_analysis/d3_clustering.py. This is Group 2 item 10 of PLAN.md Section 7
("Unsupervised clustering of TLS/PQC configuration profiles -- not yet attempted") -- genuinely
new relative to the UK paper (supervised regression) and the global paper (descriptive
classification), neither of which clusters configurations in an unsupervised way.

QUESTION
  Do domains fall into a small number of natural "configuration profiles" (e.g. modern/PQ-hardened,
  legacy/vulnerable, mixed-posture) when clustered purely on their measured TLS/PQC/cert/DNSSEC/HTTP
  features, with no sector or tier label used as an input? Sector/tier are reported AFTER clustering,
  as a description of who ends up in which cluster -- never as a clustering input, so cluster
  membership is not circularly defined by the sector labels we're trying to relate it to.

INPUT
  data/measurement/processed/phase_d_joined.csv (7,999 live domains, from the same join d1/d2 use)

FEATURES (all boolean/binary, 0/1; this is a deliberate, stated scope choice -- see LIMITATIONS)
  pq_default              pq_class == 'pq_default'
  tls13                   tls_version == 'TLSv1.3'
  cert_trusted            cert_trusted == True
  cert_strong_key         c1_leaf_strength >= 128 (NIST SP 800-57 tier, Phase C1)
  accepts_legacy_tls      accepts_tls_1_0_or_1_1 == True
  accepts_sslv3           c2_accepts_sslv3 == True
  accepts_3des            c2_accepts_3des == True
  dnssec_validated        c3_ad_validated == True
  hsts_present            hsts_present == True
  waf_detected            waf_detected == True

MISSING DATA
  A domain missing a given feature's underlying measurement (e.g. no certificate presented, so
  cert_trusted/cert_strong_key are undefined) gets that feature set to 0 ("not present/not true"),
  NOT dropped -- clustering needs a complete matrix, and "no certificate" is itself part of a
  domain's real configuration profile, not a missing-data problem to exclude. This is a scope
  choice, stated here rather than silently assumed: a future pass could instead carry missing-ness
  as its own feature.

METHOD, AND WHY k IS NOT CHOSEN BY MAXIMIZING SILHOUETTE
  K-means on the binary feature matrix (StandardScaler-normalized so no single feature with higher
  variance dominates the distance metric). An initial pass chose k by maximizing silhouette score
  over k=2..19 -- but silhouette climbed monotonically the whole way (0.44 at k=2 to 0.87 at k=19),
  never turning down. The cause, checked directly: only 99 distinct binary profiles actually occur
  among the 7,999 domains (not the 1,024 combinatorially possible), a handful extremely dominant
  (the top 5 alone cover ~65% of domains -- see phase_d_distinct_profiles.csv). With genuinely
  discrete data like this, adding more clusters can ALWAYS carve out a slightly purer subset, right
  up to one cluster per distinct combination -- so maximizing silhouette here would overfit to the
  discreteness, not find a small number of natural profiles (the actual question this step asks).
  k is instead chosen by the ELBOW in inertia (first k, searched over 2..20, where the marginal
  reduction in inertia from k-1 drops below 15% and stays roughly there -- i.e. where adding another
  cluster stops buying much). A first attempt capped the search at k=8 for interpretability, but the
  drop-per-step was still above 15% all the way to that boundary (hitting the same "edge of range"
  problem silhouette had); checked out to k=29, the real elbow is at k=12 (11.8% drop, and it stays
  under ~15% afterward with minor fluctuation) -- so the search range was widened rather than keeping
  a capped, falsely-reassuring answer. 12 clusters is more than an intuitive "handful of profiles,"
  but it's an honest, checkable elbow rather than an arbitrary round number -- see LIMITATIONS.
  Both the inertia curve and the (non-peaking) silhouette curve are saved, so this choice is
  checkable, not just asserted -- and the raw distinct-profile frequency table is saved too, since
  with only 99 real combinations, it is arguably more informative than any clustering of them.

OUTPUTS (results/tables/ and results/figures/)
  phase_d_cluster_assignments.csv   domain, cluster
  phase_d_cluster_profiles.csv      per cluster: size, mean of each feature, top sector/tier mix
  phase_d_cluster_k_selection.csv   silhouette score AND inertia for each candidate k (2..20)
  phase_d_distinct_profiles.csv     every one of the 99 raw combinations actually observed, by size
  phase_d_clustering_report.md      human-readable summary
  phase_d_cluster_k_selection.png   inertia-vs-k plot (elbow marked) and silhouette-vs-k (for reference)

LIMITATIONS (stated, not discovered after the fact)
  - Silhouette score cannot be used to pick k here -- it never peaks within any reasonable range
    (see METHOD above). The elbow-in-inertia method used instead is itself a heuristic (the 15%
    threshold is a round-number choice, not derived), so the chosen k is a reasonable, checkable
    default for an interpretable number of profiles, not a provably optimal count. --k lets this be
    overridden.
  - All features are collapsed to binary. This loses magnitude information (e.g. RSA-1024 vs
    RSA-2048 vs EC-384 all become cert_strong_key=0/0/1); a finer-grained version could use the
    actual tier/ordinal values instead. Binary was chosen because most of this project's own
    measured facts ARE naturally binary (accepted/not, trusted/not, validated/not), and mixing a
    handful of ordinal features in with mostly-binary ones would let them dominate the Euclidean
    distance unless carefully re-scaled -- a real design decision, not an oversight.
  - K-means assumes roughly spherical, similarly-sized clusters in feature space; a profile that is
    a small, tight outlier group could get merged into a larger cluster. No alternative algorithm
    (DBSCAN, hierarchical) was tried in this first pass.
  - Sector/tier/provider are NEVER inputs to the clustering -- only used afterward, to describe what
    naturally ended up in each cluster. Don't read a cluster's sector composition as proof the
    clustering "found" sectors; it may just as easily reflect the shared-hosting concentration
    already documented in PLAN.md Section 5.4.
"""
import argparse
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

INPUT_DEFAULT = "data/measurement/processed/phase_d_joined.csv"
OUT_TABLES_DEFAULT = "results/tables"
OUT_FIGURES_DEFAULT = "results/figures"

FEATURES = [
    "pq_default", "tls13", "cert_trusted", "cert_strong_key", "accepts_legacy_tls",
    "accepts_sslv3", "accepts_3des", "dnssec_validated", "hsts_present", "waf_detected",
]


def build_features(df):
    f = pd.DataFrame(index=df.index)
    f["pq_default"] = (df["pq_class"] == "pq_default").astype(int)
    f["tls13"] = (df["tls_version"] == "TLSv1.3").astype(int)
    f["cert_trusted"] = df["cert_trusted"].fillna(False).astype(bool).astype(int)
    f["cert_strong_key"] = (df["c1_leaf_strength"].fillna(0) >= 128).astype(int)
    f["accepts_legacy_tls"] = df["accepts_tls_1_0_or_1_1"].fillna(False).astype(bool).astype(int)
    f["accepts_sslv3"] = df["c2_accepts_sslv3"].fillna(False).astype(bool).astype(int)
    f["accepts_3des"] = df["c2_accepts_3des"].fillna(False).astype(bool).astype(int)
    f["dnssec_validated"] = df["c3_ad_validated"].fillna(False).astype(bool).astype(int)
    f["hsts_present"] = df["hsts_present"].fillna(False).astype(bool).astype(int)
    f["waf_detected"] = df["waf_detected"].fillna(False).astype(bool).astype(int)
    return f[FEATURES]


def choose_k(X, k_range=range(2, 21), seed=7, elbow_threshold=0.15):
    rows = []
    for k in k_range:
        km = KMeans(n_clusters=k, random_state=seed, n_init=10)
        labels = km.fit_predict(X)
        sil = silhouette_score(X, labels, sample_size=min(len(X), 4000), random_state=seed)
        rows.append({"k": k, "silhouette": round(sil, 4), "inertia": round(km.inertia_, 1)})
    table = pd.DataFrame(rows)

    # elbow: first k (after the first) where inertia's drop from the previous k is < elbow_threshold
    # of the previous k's inertia -- see METHOD in the module docstring for why silhouette isn't used.
    elbow_k = table["k"].iloc[-1]  # fallback: largest k tried, if no elbow is found
    for i in range(1, len(table)):
        prev_inertia = table["inertia"].iloc[i - 1]
        drop = (prev_inertia - table["inertia"].iloc[i]) / prev_inertia
        if drop < elbow_threshold:
            elbow_k = table["k"].iloc[i]
            break
    return table, int(elbow_k)


def distinct_profiles(df, feats):
    combos = feats.apply(lambda r: tuple(r), axis=1)
    counts = combos.value_counts()
    rows = []
    for combo, n in counts.items():
        row = dict(zip(FEATURES, combo))
        row["n"] = int(n)
        row["pct_of_corpus"] = round(100 * n / len(df), 2)
        rows.append(row)
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=INPUT_DEFAULT)
    ap.add_argument("--out-tables", default=OUT_TABLES_DEFAULT)
    ap.add_argument("--out-figures", default=OUT_FIGURES_DEFAULT)
    ap.add_argument("--k", type=int, default=None, help="force a specific k instead of auto-selecting")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    df = pd.read_csv(args.input, low_memory=False)
    os.makedirs(args.out_tables, exist_ok=True)
    os.makedirs(args.out_figures, exist_ok=True)

    feats = build_features(df)
    X = StandardScaler().fit_transform(feats.values)

    k_table, elbow_k = choose_k(X, seed=args.seed)
    k_table.to_csv(os.path.join(args.out_tables, "phase_d_cluster_k_selection.csv"), index=False)

    profiles_df = distinct_profiles(df, feats)
    profiles_df.to_csv(os.path.join(args.out_tables, "phase_d_distinct_profiles.csv"), index=False)

    best_k = args.k or elbow_k
    km = KMeans(n_clusters=best_k, random_state=args.seed, n_init=10)
    labels = km.fit_predict(X)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    ax1.plot(k_table["k"], k_table["inertia"], marker="o", color="black")
    ax1.axvline(best_k, color="gray", linestyle="--", linewidth=1)
    ax1.set_xlabel("k"); ax1.set_ylabel("inertia"); ax1.set_title(f"Elbow (chosen k={best_k})")
    ax2.plot(k_table["k"], k_table["silhouette"], marker="o", color="black")
    ax2.set_xlabel("k"); ax2.set_ylabel("silhouette")
    ax2.set_title("Silhouette (reference only -- doesn't peak here, see docstring)")
    plt.tight_layout()
    plt.savefig(os.path.join(args.out_figures, "phase_d_cluster_k_selection.png"), dpi=150)
    plt.close()

    assign = pd.DataFrame({"domain": df["domain"], "cluster": labels})
    assign.to_csv(os.path.join(args.out_tables, "phase_d_cluster_assignments.csv"), index=False)

    profile_rows = []
    for c in sorted(set(labels)):
        mask = labels == c
        row = {"cluster": c, "n": int(mask.sum()), "pct_of_corpus": round(100 * mask.sum() / len(df), 1)}
        for feat in FEATURES:
            row[feat] = round(feats.loc[mask, feat].mean(), 2)
        top_sectors = df.loc[mask, "category"].value_counts(normalize=True).head(3)
        row["top_sectors"] = "; ".join(f"{s}={round(100*v,1)}%" for s, v in top_sectors.items())
        top_tiers = df.loc[mask, "tier"].value_counts(normalize=True).head(2)
        row["top_tiers"] = "; ".join(f"{s}={round(100*v,1)}%" for s, v in top_tiers.items())
        profile_rows.append(row)
    profiles = pd.DataFrame(profile_rows).sort_values("n", ascending=False)
    profiles.to_csv(os.path.join(args.out_tables, "phase_d_cluster_profiles.csv"), index=False)

    n_distinct = len(profiles_df)
    lines = [
        f"# Phase D clustering: TLS/PQC configuration profiles (`{args.input}`, {len(df)} live domains)",
        "",
        f"Only **{n_distinct} distinct binary profiles** actually occur (of {2**len(FEATURES)} "
        "combinatorially possible) -- see `phase_d_distinct_profiles.csv` for the full raw list. "
        "Because the data is this discrete, silhouette score never peaks as k grows (checked up to "
        "k=19: 0.44 -> 0.87, monotonic) -- so k is chosen by the elbow in INERTIA instead "
        f"(chosen k={best_k}). See the module docstring for why.",
        "",
        "| k | silhouette (reference only) | inertia |",
        "|---|---|---|",
    ] + [f"| {r.k}{' *elbow*' if r.k == best_k else ''} | {r.silhouette} | {r.inertia} |"
         for r in k_table.itertuples()] + [
        "",
        f"## {best_k} cluster profiles (mean of each binary feature, 0.0-1.0; sector/tier shown for "
        "description only, never used as a clustering input)",
        "",
        "| cluster | n | % of corpus | " + " | ".join(FEATURES) + " | top sectors | top tiers |",
        "|" + "---|" * (len(FEATURES) + 5),
    ]
    for r in profiles.itertuples():
        feat_vals = " | ".join(str(getattr(r, f)) for f in FEATURES)
        lines.append(f"| {r.cluster} | {r.n} | {r.pct_of_corpus}% | {feat_vals} | {r.top_sectors} | {r.top_tiers} |")

    report = "\n".join(lines)
    with open(os.path.join(args.out_tables, "phase_d_clustering_report.md"), "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print(f"\nWrote: {args.out_tables}/phase_d_cluster_*.csv, {args.out_figures}/phase_d_cluster_k_selection.png")


if __name__ == "__main__":
    main()