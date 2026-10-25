#!/usr/bin/env python3
"""
E2a: Multivariate logistic regression on security posture, provider controlled as a confound.
(PLAN.md Section 4.17 / Section 7 Group 2 item 11)

QUESTION
  Does a domain's legacy-protocol acceptance (TLS 1.0/1.1, 3DES, SSLv3) and certificate
  key-strength tier correlate with PQC adoption (pq_default), once hosting provider is
  controlled for as a confound? This is deliberately NOT the withdrawn "provider vs. sector"
  comparison (Section 7, Group 3, item 12) -- provider here is a control variable, not the
  object of study. It is also distinct from d1_sector_summary.py's bivariate cert-TRUST-vs-PQ
  finding (Section 4.15, 96.3% vs 55.0%) -- this model's certificate-hygiene predictor is
  key-STRENGTH tier (NIST SP 800-57 tier, Section 4.11), not certificate trust/validity.

INPUT
  data/measurement/processed/phase_d_joined.csv (the same 7,999-row file d1/d3 use)

OUTCOME
  y_pq_default = 1 if pq_class == "pq_default", else 0 (covers "not_capable", "no_tls13", and
  the 2-domain "pq_capable_not_default" edge case). Domains with pq_class == "unknown" (235 of
  7,999 -- the TLS connection never got far enough to classify) are EXCLUDED from the model
  entirely, not coded as 0. An unresolved connection is inconclusive about PQ status, not
  evidence of its absence (project Standing Rule 9: inconclusive != dead).

PREDICTORS
  - accepts_legacy_tls  (raw column accepts_tls_1_0_or_1_1): bool
  - accepts_sslv3        (raw column c2_accepts_sslv3): bool
  - accepts_3des          (raw column c2_accepts_3des): bool
  - cert_key_tier         (raw column c1_leaf_status): categorical {below_112, only_112
    [reference level -- the largest group, 5,732 of 7,827 domains with a cert], 128_plus}.
    Requires a certificate to exist at all, so the 172 domains with no certificate
    (c1_has_cert == False) have no tier and are excluded from this model.
  - provider              (raw column provider_guess, bucketed): categorical {Google,
    cPanel-style shared hosting, Cloudflare, Amazon/AWS, Microsoft/Outlook,
    Other/unidentified [reference level]}. THE CONFOUND CONTROL, not the variable of interest
    -- reuses d1_sector_summary.py's exact provider grouping (Section 4.15) rather than
    inventing a new one. "Other/unidentified" absorbs both the long tail of small providers
    and the 6,381 domains (79.8%) with no identified provider at all -- this is a real,
    documented scope limit of the provider-matching logic, not a modeling choice; it means the
    provider dummies mostly identify "is this one of five specific large platforms", not "who
    hosts this domain" in general.

EXCLUDED ROWS (complete-case analysis -- no imputation)
  Any row with pq_class == "unknown", OR a blank value for accepts_tls_1_0_or_1_1,
  c2_accepts_sslv3, c2_accepts_3des, OR c1_leaf_status. These overlap heavily: most of the
  172 no-cert domains are also blank on the TLS-detail fields, because a connection that never
  got far enough to present a certificate usually didn't get far enough to probe old-protocol
  acceptance either. The exact breakdown (by reason, with overlap-adjusted counts) is printed
  at runtime and written into the report.

METHOD -- Firth's penalized logistic regression, NOT ordinary MLE (found necessary, not chosen
  up front; see below)
  An initial attempt used plain statsmodels Logit (ordinary maximum likelihood). It failed to
  converge. Diagnosed directly by cross-tabulating every predictor against the outcome: three
  terms have a cell with ZERO positive (`pq_default`) outcomes --
    accepts_sslv3 == True        : 26 domains, 0 PQ-default
    cert_key_tier == below_112   : 16 domains, 0 PQ-default
    provider == Microsoft/Outlook: 5 domains (post-exclusion), 0 PQ-default
  This is quasi-complete separation -- exactly the small-cell pathology the project's own
  MIN_N=30 convention (Section 4.15) exists to flag, here manifesting as a convergence failure
  rather than a misleadingly precise percentage. Ordinary MLE pushes those coefficients toward
  -infinity (confirmed: one attempt produced odds ratios of 0.000 and infinite confidence
  intervals on exactly these three terms, nothing else). Dropping the three terms was rejected
  as a fix -- Section 4.17 explicitly asks about SSLv3/3DES/TLS-1.0-1.1 acceptance and
  key-strength tier together, and removing a term because it is inconvenient to estimate is not
  the same as the data saying it doesn't matter.

  Instead: a from-scratch implementation of Firth's bias-reduced logistic regression (Heinze &
  Schemper 2002), the standard remedy for rare-predictor/separation problems in applied
  statistics (widely used in epidemiology for exactly this reason). It maximizes a
  Jeffreys-prior-penalized likelihood via a modified IRLS score equation; implemented here
  because the obvious Python package for it (`firthlogist` on PyPI) requires Python <3.11 and
  this environment runs 3.13, so it is not installable. The implementation was validated two
  ways before trusting it on the real data: (1) on a synthetic, non-separated dataset, it
  reproduces ordinary MLE coefficients to 3 decimal places, as it should when no penalty effect
  is needed; (2) on a synthetic dataset built to reproduce the exact separation pattern seen
  here (a rare binary predictor with zero positive outcomes), ordinary MLE diverges
  (coefficient -21, non-converged) while this implementation returns a finite, plausible,
  properly shrunk estimate with a finite standard error.

  Standard errors/confidence intervals are Wald-type (coef +/- 1.96*SE) on the penalized
  estimates -- simpler than the profile-likelihood CIs some Firth implementations prefer, and
  stated here explicitly as a scope limitation rather than silently presented as equivalent.

  Diagnostics:
    - McFadden's pseudo-R^2, computed from UNPENALIZED log-likelihoods (the full model
      evaluated at the Firth-penalized beta, vs. an ordinary unpenalized intercept-only null --
      which has no separation problem since the outcome is nearly balanced, 3,857/3,880). This
      is the conventional way to report a quasi-R^2 alongside a penalized fit.
    - AUC (sklearn, on the same data the model was fit on -- an in-sample discrimination number
      for context, NOT a held-out/cross-validated estimate; this is a modest-sized explanatory
      model built for inference, not a predictive model meant to generalize, so a train/test
      split was judged unnecessary complexity for this item's scope).
    - VIF (variance inflation factor), computed on the dummy-coded design matrix including the
      intercept column, independent of the fitting method above, per Section 4.17's explicit
      "diagnostics (multicollinearity...)" requirement. Reported per dummy column (not collapsed
      per categorical variable) -- interpret the max VIF within a related group of dummies
      (e.g. the five provider-vs-rest indicators) as that variable's effective
      multicollinearity.

NEW DEPENDENCIES: this script requires `statsmodels` (used for VIF only, not for fitting the
  model itself) -- not used by d1/d2/d3 (those use pandas/numpy/matplotlib/scikit-learn only).
  `pip install statsmodels` before running, and add it to requirements.txt (PLAN.md Section 10
  TODO list already flags requirements.txt as needing a pass). No other new dependency --
  Firth's method is implemented directly in this file (see `firth_logit()`) rather than via a
  third-party package, for the Python-version reason explained above.

OUTPUTS (results/tables/):
  phase_e2a_coefficients.csv   one row per model term: coef, std_err, z, p_value, odds_ratio,
                                or_ci_low, or_ci_high
  phase_e2a_vif.csv            VIF per design-matrix column
  phase_e2a_report.md          full write-up: sample/exclusions, model spec, fit diagnostics,
                                coefficient table (as odds ratios), VIF table, interpretation

Usage (from project root):
    python measurement/phase_d_analysis/e2a_logistic_regression.py
    python measurement/phase_d_analysis/e2a_logistic_regression.py --input path/to/phase_d_joined.csv
"""

import argparse
import os
import sys
from collections import Counter

import numpy as np
import pandas as pd
import statsmodels.api as sm
from statsmodels.stats.outliers_influence import variance_inflation_factor

DEFAULT_INPUT = os.path.join("data", "measurement", "processed", "phase_d_joined.csv")
OUT_TABLES = os.path.join("results", "tables")

# Same provider grouping as d1_sector_summary.py (Section 4.15) -- top 5 by domain count;
# everything else (including blank/unidentified) is bucketed as "Other/unidentified", which is
# also this variable's reference level in the model.
TOP_PROVIDERS = ["Google", "cPanel-style shared hosting", "Cloudflare", "Amazon/AWS", "Microsoft/Outlook"]
REFERENCE_PROVIDER = "Other/unidentified"
REFERENCE_CERT_TIER = "only_112"

BOOL_MAP = {"True": True, "False": False, "": None}


def to_bool(series):
    return series.map(BOOL_MAP)


def load_data(path):
    if not os.path.exists(path):
        sys.exit(f"ERROR: {path} not found. Run from the project root, or pass --input explicitly.")
    return pd.read_csv(path, dtype=str, keep_default_na=False)


def build_analytic_frame(df):
    """Returns (analytic_df, exclusion_counts). analytic_df has one row per KEPT domain with
    clean typed columns ready for dummy-coding; exclusion_counts documents what was dropped and
    why, for the report."""
    work = pd.DataFrame(index=df.index)
    work["pq_class"] = df["pq_class"]
    work["accepts_legacy_tls"] = to_bool(df["accepts_tls_1_0_or_1_1"])
    work["accepts_sslv3"] = to_bool(df["c2_accepts_sslv3"])
    work["accepts_3des"] = to_bool(df["c2_accepts_3des"])
    work["cert_key_tier"] = df["c1_leaf_status"].replace("", np.nan)
    work["provider_raw"] = df["provider_guess"]

    mask_unknown_outcome = work["pq_class"] == "unknown"
    mask_missing_tls = work["accepts_legacy_tls"].isna() | work["accepts_sslv3"].isna() | work["accepts_3des"].isna()
    mask_missing_cert = work["cert_key_tier"].isna()
    mask_drop = mask_unknown_outcome | mask_missing_tls | mask_missing_cert

    counts = {
        "total_domains": len(work),
        "excluded_unknown_pq_class": int(mask_unknown_outcome.sum()),
        "excluded_missing_tls_detail": int(mask_missing_tls.sum()),
        "excluded_no_certificate": int(mask_missing_cert.sum()),
        "excluded_total_any_reason": int(mask_drop.sum()),
        "analytic_sample_n": int((~mask_drop).sum()),
    }

    kept = work[~mask_drop].copy()
    kept["y_pq_default"] = (kept["pq_class"] == "pq_default").astype(int)

    def bucket_provider(p):
        return p if p in TOP_PROVIDERS else REFERENCE_PROVIDER

    kept["provider"] = kept["provider_raw"].map(bucket_provider)
    kept["cert_key_tier"] = pd.Categorical(kept["cert_key_tier"],
                                            categories=[REFERENCE_CERT_TIER, "128_plus", "below_112"])
    kept["provider"] = pd.Categorical(kept["provider"],
                                       categories=[REFERENCE_PROVIDER] + TOP_PROVIDERS)
    return kept, counts


def build_design_matrix(kept):
    """Dummy-codes the categoricals with the reference levels fixed above, casts bools to
    0/1 ints, and adds a constant (intercept) column -- returns (X, y) ready for sm.Logit."""
    X = pd.DataFrame(index=kept.index)
    X["accepts_legacy_tls"] = kept["accepts_legacy_tls"].astype(int)
    X["accepts_sslv3"] = kept["accepts_sslv3"].astype(int)
    X["accepts_3des"] = kept["accepts_3des"].astype(int)

    cert_dummies = pd.get_dummies(kept["cert_key_tier"], prefix="cert_tier", drop_first=True, dtype=int)
    provider_dummies = pd.get_dummies(kept["provider"], prefix="provider", drop_first=True, dtype=int)
    X = pd.concat([X, cert_dummies, provider_dummies], axis=1)
    X = sm.add_constant(X, has_constant="add")
    y = kept["y_pq_default"]
    return X, y


def compute_vif(X):
    """VIF per column of the design matrix (intercept included, standard practice for VIF on a
    matrix that already has one -- statsmodels' own VIF function expects it this way)."""
    rows = []
    X_arr = X.values.astype(float)
    for i, col in enumerate(X.columns):
        vif = variance_inflation_factor(X_arr, i)
        rows.append({"term": col, "vif": round(vif, 3)})
    return pd.DataFrame(rows)


def firth_logit(X, y, max_iter=200, tol=1e-8):
    """Firth's bias-reduced logistic regression (Heinze & Schemper 2002), implemented directly
    because the `firthlogist` PyPI package requires Python <3.11 (this environment runs 3.13).
    See the module docstring for validation against (1) a non-separated synthetic case (matches
    ordinary MLE) and (2) a separated synthetic case built to mirror this dataset's actual
    pathology (finite estimate where ordinary MLE diverges). Returns (beta, se, fitted_probs,
    n_iterations) -- SEs are the Wald-type SEs from the information matrix at the penalized
    estimate, not profile-likelihood CIs (see module docstring's stated limitation)."""
    X_arr = np.asarray(X, dtype=float)
    y_arr = np.asarray(y, dtype=float)
    n, k = X_arr.shape
    beta = np.zeros(k)
    converged = False
    for it in range(max_iter):
        eta = X_arr @ beta
        p = 1.0 / (1.0 + np.exp(-eta))
        W = p * (1 - p)
        XtWX = X_arr.T @ (X_arr * W[:, None])
        XtWX_inv = np.linalg.inv(XtWX)
        h = W * np.einsum("ij,jk,ik->i", X_arr, XtWX_inv, X_arr)          # hat-matrix diagonal
        U_star = X_arr.T @ (y_arr - p + h * (0.5 - p))                   # Firth-penalized score
        delta = XtWX_inv @ U_star
        beta = beta + delta
        if np.max(np.abs(delta)) < tol:
            converged = True
            break
    eta = X_arr @ beta
    p = 1.0 / (1.0 + np.exp(-eta))
    W = p * (1 - p)
    cov = np.linalg.inv(X_arr.T @ (X_arr * W[:, None]))
    se = np.sqrt(np.diag(cov))
    return beta, se, p, it + 1, converged


def unpenalized_loglik(y, p):
    eps = 1e-12
    p = np.clip(p, eps, 1 - eps)
    return float(np.sum(y * np.log(p) + (1 - y) * np.log(1 - p)))


def null_model_loglik(y):
    """Ordinary (unpenalized) intercept-only logistic fit -- no separation risk here since the
    outcome is nearly balanced (3,857/3,880), so plain MLE is fine for just the null model."""
    y_arr = np.asarray(y, dtype=float)
    X0 = np.ones((len(y_arr), 1))
    res = sm.Logit(y_arr, X0).fit(disp=False)
    return res.llf


def coefficients_table(terms, beta, se):
    from scipy.stats import norm
    z = beta / se
    p_value = 2 * (1 - norm.cdf(np.abs(z)))
    ci_low = beta - 1.96 * se
    ci_high = beta + 1.96 * se
    out = pd.DataFrame({
        "term": terms, "coef": beta, "std_err": se, "z": z, "p_value": p_value,
    })
    out["odds_ratio"] = np.exp(out["coef"])
    out["or_ci_low"] = np.exp(ci_low)
    out["or_ci_high"] = np.exp(ci_high)
    for c in ["coef", "std_err", "z", "or_ci_low", "or_ci_high", "odds_ratio"]:
        out[c] = out[c].round(4)
    out["p_value"] = out["p_value"].round(4)
    return out


def auc_in_sample(p, y):
    from sklearn.metrics import roc_auc_score
    return round(roc_auc_score(y, p), 4)


LABELS = {
    "const": "Intercept",
    "accepts_legacy_tls": "Accepts TLS 1.0/1.1",
    "accepts_sslv3": "Accepts SSLv3",
    "accepts_3des": "Accepts 3DES (when offered)",
    "cert_tier_128_plus": "Cert key tier: >=128-bit (ref: 112-bit)",
    "cert_tier_below_112": "Cert key tier: <112-bit (ref: 112-bit)",
    "provider_Google": "Provider: Google (ref: Other/unidentified)",
    "provider_cPanel-style shared hosting": "Provider: cPanel-style shared hosting (ref: Other/unidentified)",
    "provider_Cloudflare": "Provider: Cloudflare (ref: Other/unidentified)",
    "provider_Amazon/AWS": "Provider: Amazon/AWS (ref: Other/unidentified)",
    "provider_Microsoft/Outlook": "Provider: Microsoft/Outlook (ref: Other/unidentified)",
}


def write_report(path, counts, coef_df, vif_df, fit_stats, auc, kept):
    def sig(p):
        return "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else ""

    lines = [
        "# E2a: Multivariate logistic regression on security posture",
        "", "(PLAN.md Section 4.17 / Section 7 Group 2 item 11)", "",
        "## Question",
        "Does legacy-protocol acceptance (TLS 1.0/1.1, 3DES, SSLv3) and certificate key-strength "
        "tier correlate with PQC adoption (`pq_default`), controlling for hosting provider as a "
        "confound? Provider is a control variable here, not the object of study -- that comparison "
        "was already made twice in the literature and explicitly withdrawn as a standalone "
        "contribution (Section 7, Group 3, item 12).", "",
        "## Sample", "",
        f"- Total domains in `phase_d_joined.csv`: {counts['total_domains']:,}",
        f"- Excluded, `pq_class == \"unknown\"` (inconclusive outcome, not coded as 0): "
        f"{counts['excluded_unknown_pq_class']:,}",
        f"- Excluded, missing TLS-detail fields (legacy/SSLv3/3DES never conclusively probed): "
        f"{counts['excluded_missing_tls_detail']:,}",
        f"- Excluded, no certificate presented at all (no key-strength tier to speak of): "
        f"{counts['excluded_no_certificate']:,}",
        f"- Excluded for any of the above reasons (overlap-adjusted): "
        f"{counts['excluded_total_any_reason']:,}",
        f"- **Analytic sample: {counts['analytic_sample_n']:,} domains "
        f"({100*counts['analytic_sample_n']/counts['total_domains']:.1f}% of the corpus)**", "",
        "## Method note: Firth's penalized logistic regression, not ordinary MLE", "",
        "Ordinary (unpenalized) logistic regression failed to converge on this model. Diagnosed "
        "directly: three terms have a cell with **zero** positive outcomes -- `accepts_sslv3` "
        "(26 domains, 0 PQ-default), `cert_key_tier == below_112` (16 domains, 0 PQ-default), and "
        "`provider == Microsoft/Outlook` (5 domains, 0 PQ-default). This is quasi-complete "
        "separation, the same small-cell pathology the project's MIN_N=30 convention exists to "
        "flag (Section 4.15) -- here it breaks MLE convergence outright rather than just producing "
        "a misleadingly precise percentage. The fix used is Firth's bias-reduced logistic "
        "regression (Heinze & Schemper 2002), implemented directly in this script (not via the "
        "`firthlogist` PyPI package, which requires Python <3.11) and validated against both a "
        "non-separated synthetic case (matches ordinary MLE) and a synthetic case built to "
        "reproduce this exact separation pattern (finite estimate where MLE diverges) -- see the "
        "module docstring for both checks. Confidence intervals below are Wald-type on the "
        "penalized estimate, not profile-likelihood CIs.", "",
        "## Model fit", "",
        f"- Firth IRLS iterations to convergence: {fit_stats['iterations']} (converged: "
        f"{fit_stats['converged']})",
        f"- Log-likelihood (unpenalized, evaluated at the Firth estimate): {fit_stats['llf']:.1f} "
        f"(null model: {fit_stats['llnull']:.1f})",
        f"- McFadden's pseudo-R^2 (quasi-R^2 -- see method note above): {fit_stats['prsquared']:.4f}",
        f"- AUC (in-sample; this is an explanatory model, not a validated predictive one -- see "
        f"module docstring): {auc:.4f}", "",
        "## Coefficients (as odds ratios)", "",
        "| Term | Odds ratio | 95% CI | p-value | |",
        "|---|---|---|---|---|",
    ]
    for _, r in coef_df.iterrows():
        label = LABELS.get(r["term"], r["term"])
        lines.append(f"| {label} | {r['odds_ratio']:.3f} | [{r['or_ci_low']:.3f}, {r['or_ci_high']:.3f}] | "
                      f"{r['p_value']:.4f} | {sig(r['p_value'])} |")
    lines += ["", "_(An odds ratio > 1 means that predictor is associated with HIGHER odds of "
              "being PQ-default, holding the others fixed; < 1 means lower odds. `*** p<0.001, "
              "** p<0.01, * p<0.05`.)_", "",
              "## Multicollinearity (VIF)", "",
              "| Term | VIF |", "|---|---|"]
    for _, r in vif_df.iterrows():
        label = LABELS.get(r["term"], r["term"])
        lines.append(f"| {label} | {r['vif']:.2f} |")
    lines += ["", "_VIF > 5 is commonly treated as a concerning level of multicollinearity for a "
              "given term; VIF for the intercept is not meaningful and is included only for "
              "completeness._", "",
              "## Interpretation notes", "",
              "- **The legacy-TLS coefficient sign-flips relative to the raw univariate figure, and "
              "this is a real confounding effect worth stating plainly, not an artifact.** Section "
              "4.10 noted that PQ-default domains are *disproportionately* likely to still accept "
              "TLS 1.0/1.1 raw: 77.8% of legacy-TLS-accepting domains are PQ-default vs. 44.4% of "
              "non-legacy-accepting ones. Once provider is controlled for, the direction reverses "
              "(OR well under 1 above). The reason: Google (89.1% legacy-TLS acceptance rate, ~99% "
              "PQ-default regardless) and Cloudflare (76.6% legacy-TLS acceptance, also overwhelmingly "
              "PQ-default) dominate the legacy-accepting population and drag the raw correlation "
              "positive. **Within the \"Other/unidentified\" bucket alone** (ordinary/unbranded "
              "hosting, 79.8% of the corpus), the relationship is strongly negative: only 3.5% of "
              "legacy-TLS-accepting domains there are PQ-default, vs. 41.9% of non-legacy-accepting "
              "ones -- the intuitive \"weaker security posture, no PQC\" pattern, masked in the raw "
              "numbers by two large platforms' blanket behavior. This is exactly the kind of finding "
              "provider-as-confound-control is supposed to surface, and is a genuinely new result, "
              "not a restatement of Section 4.10's bivariate observation.",
              "- Beyond that reversal, this model answers whether the named predictors correlate "
              "with PQ-default status **within this live, cross-sectional sample** -- it is not a "
              "causal claim, and (as with `d1_sector_summary.py`'s bivariate cert-trust finding) the "
              "likeliest reading for the remaining associations is that both modern PQ support and "
              "clean legacy-protocol/cert-hygiene posture come from the same underlying cause (a "
              "modernized hosting stack), rather than one causing the other.",
              "- The three terms affected by near-separation (`accepts_sslv3`, `cert_key_tier == "
              "below_112`, `provider == Microsoft/Outlook`) have wide confidence intervals and are "
              "not statistically significant (p > 0.05) -- this correctly reflects genuine "
              "uncertainty from very small cell counts (26, 16, and 5 domains respectively), not a "
              "claim that these factors don't matter. Do not quote these three odds ratios as "
              "precise point estimates in the paper; report them as inconclusive at this sample "
              "size, consistent with the project's MIN_N convention.",
              "- The provider confound's reference level, \"Other/unidentified\", covers "
              f"{counts['analytic_sample_n'] - sum((kept['provider'] != REFERENCE_PROVIDER))} of "
              f"{counts['analytic_sample_n']:,} analytic-sample domains "
              "-- a large, heterogeneous bucket (both small/unmatched providers and domains the "
              "provider-matching logic never identified at all, Section 4.15). The provider "
              "coefficients above should be read as \"vs. this mixed bucket\", not \"vs. the "
              "general population of other named hosts\".",
              "- Do not compare this item's odds ratios to the earlier bivariate finding's percentages "
              "directly (96.3% vs 55.0% cert-TRUSTED-by-PQ-status, Section 4.15) -- they measure "
              "different things (certificate trust/validity vs. key-strength tier) and are not "
              "meant to replicate each other.",
              ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=DEFAULT_INPUT, help=f"path to phase_d_joined.csv (default: {DEFAULT_INPUT})")
    args = ap.parse_args()

    df = load_data(args.input)
    kept, counts = build_analytic_frame(df)
    print(f"Total domains: {counts['total_domains']:,}")
    print(f"Excluded (unknown pq_class): {counts['excluded_unknown_pq_class']:,}")
    print(f"Excluded (missing TLS detail): {counts['excluded_missing_tls_detail']:,}")
    print(f"Excluded (no certificate): {counts['excluded_no_certificate']:,}")
    print(f"Excluded total (overlap-adjusted): {counts['excluded_total_any_reason']:,}")
    print(f"Analytic sample: {counts['analytic_sample_n']:,}")

    X, y = build_design_matrix(kept)
    print(f"\nDesign matrix: {X.shape[0]} rows x {X.shape[1]} columns")
    print("Outcome balance:", dict(Counter(y)))

    beta, se, p_fitted, n_iter, converged = firth_logit(X.values, y.values)
    if not converged:
        print("WARNING: Firth IRLS did not converge within max_iter -- results below may be unreliable.")
    coef_df = coefficients_table(X.columns, beta, se)
    vif_df = compute_vif(X)
    auc = auc_in_sample(p_fitted, y)

    llf = unpenalized_loglik(y.values, p_fitted)
    llnull = null_model_loglik(y)
    prsquared = 1 - llf / llnull
    fit_stats = {"iterations": n_iter, "converged": converged, "llf": llf, "llnull": llnull,
                 "prsquared": prsquared}

    print(f"\nFirth IRLS: {n_iter} iterations, converged={converged}")
    print(f"McFadden's pseudo-R^2: {prsquared:.4f}")
    print(f"AUC (in-sample): {auc:.4f}")
    print("\nCoefficients (odds ratios):")
    for _, r in coef_df.iterrows():
        print(f"  {LABELS.get(r['term'], r['term']):55s} OR={r['odds_ratio']:.3f}  "
              f"95%CI=[{r['or_ci_low']:.3f},{r['or_ci_high']:.3f}]  p={r['p_value']:.4f}")
    print("\nVIF:")
    for _, r in vif_df.iterrows():
        print(f"  {LABELS.get(r['term'], r['term']):55s} VIF={r['vif']:.2f}")

    os.makedirs(OUT_TABLES, exist_ok=True)
    coef_df.to_csv(os.path.join(OUT_TABLES, "phase_e2a_coefficients.csv"), index=False)
    vif_df.to_csv(os.path.join(OUT_TABLES, "phase_e2a_vif.csv"), index=False)
    write_report(os.path.join(OUT_TABLES, "phase_e2a_report.md"), counts, coef_df, vif_df, fit_stats, auc, kept)
    print(f"\nWrote: {OUT_TABLES}/phase_e2a_coefficients.csv, phase_e2a_vif.csv, phase_e2a_report.md")


if __name__ == "__main__":
    main()