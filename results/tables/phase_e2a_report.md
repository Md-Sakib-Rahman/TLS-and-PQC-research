# E2a: Multivariate logistic regression on security posture

(PLAN.md Section 4.17 / Section 7 Group 2 item 11)

## Question
Does legacy-protocol acceptance (TLS 1.0/1.1, 3DES, SSLv3) and certificate key-strength tier correlate with PQC adoption (`pq_default`), controlling for hosting provider as a confound? Provider is a control variable here, not the object of study -- that comparison was already made twice in the literature and explicitly withdrawn as a standalone contribution (Section 7, Group 3, item 12).

## Sample

- Total domains in `phase_d_joined.csv`: 7,999
- Excluded, `pq_class == "unknown"` (inconclusive outcome, not coded as 0): 235
- Excluded, missing TLS-detail fields (legacy/SSLv3/3DES never conclusively probed): 57
- Excluded, no certificate presented at all (no key-strength tier to speak of): 172
- Excluded for any of the above reasons (overlap-adjusted): 262
- **Analytic sample: 7,737 domains (96.7% of the corpus)**

## Method note: Firth's penalized logistic regression, not ordinary MLE

Ordinary (unpenalized) logistic regression failed to converge on this model. Diagnosed directly: three terms have a cell with **zero** positive outcomes -- `accepts_sslv3` (26 domains, 0 PQ-default), `cert_key_tier == below_112` (16 domains, 0 PQ-default), and `provider == Microsoft/Outlook` (5 domains, 0 PQ-default). This is quasi-complete separation, the same small-cell pathology the project's MIN_N=30 convention exists to flag (Section 4.15) -- here it breaks MLE convergence outright rather than just producing a misleadingly precise percentage. The fix used is Firth's bias-reduced logistic regression (Heinze & Schemper 2002), implemented directly in this script (not via the `firthlogist` PyPI package, which requires Python <3.11) and validated against both a non-separated synthetic case (matches ordinary MLE) and a synthetic case built to reproduce this exact separation pattern (finite estimate where MLE diverges) -- see the module docstring for both checks. Confidence intervals below are Wald-type on the penalized estimate, not profile-likelihood CIs.

## Model fit

- Firth IRLS iterations to convergence: 15 (converged: True)
- Log-likelihood (unpenalized, evaluated at the Firth estimate): -4364.8 (null model: -5362.8)
- McFadden's pseudo-R^2 (quasi-R^2 -- see method note above): 0.1861
- AUC (in-sample; this is an explanatory model, not a validated predictive one -- see module docstring): 0.6951

## Coefficients (as odds ratios)

| Term | Odds ratio | 95% CI | p-value | |
|---|---|---|---|---|
| Intercept | 0.735 | [0.695, 0.778] | 0.0000 | *** |
| Accepts TLS 1.0/1.1 | 0.120 | [0.072, 0.201] | 0.0000 | *** |
| Accepts SSLv3 | 0.958 | [0.045, 20.465] | 0.9781 |  |
| Accepts 3DES (when offered) | 0.228 | [0.075, 0.692] | 0.0091 | ** |
| Cert key tier: >=128-bit (ref: 112-bit) | 0.866 | [0.748, 1.002] | 0.0536 |  |
| Cert key tier: <112-bit (ref: 112-bit) | 0.280 | [0.015, 5.410] | 0.3997 |  |
| Provider: Google (ref: Other/unidentified) | 1282.425 | [581.566, 2827.907] | 0.0000 | *** |
| Provider: cPanel-style shared hosting (ref: Other/unidentified) | 2.183 | [1.776, 2.684] | 0.0000 | *** |
| Provider: Cloudflare (ref: Other/unidentified) | 728.180 | [132.964, 3987.894] | 0.0000 | *** |
| Provider: Amazon/AWS (ref: Other/unidentified) | 23.780 | [2.534, 223.142] | 0.0055 | ** |
| Provider: Microsoft/Outlook (ref: Other/unidentified) | 0.248 | [0.008, 7.782] | 0.4280 |  |

_(An odds ratio > 1 means that predictor is associated with HIGHER odds of being PQ-default, holding the others fixed; < 1 means lower odds. `*** p<0.001, ** p<0.01, * p<0.05`.)_

## Multicollinearity (VIF)

| Term | VIF |
|---|---|
| Intercept | 1.00 |
| Accepts TLS 1.0/1.1 | 3.48 |
| Accepts SSLv3 | 1.23 |
| Accepts 3DES (when offered) | 1.43 |
| Cert key tier: >=128-bit (ref: 112-bit) | 1.85 |
| Cert key tier: <112-bit (ref: 112-bit) | 1.05 |
| Provider: Google (ref: Other/unidentified) | 3.77 |
| Provider: cPanel-style shared hosting (ref: Other/unidentified) | 1.02 |
| Provider: Cloudflare (ref: Other/unidentified) | 1.25 |
| Provider: Amazon/AWS (ref: Other/unidentified) | 1.00 |
| Provider: Microsoft/Outlook (ref: Other/unidentified) | 1.00 |

_VIF > 5 is commonly treated as a concerning level of multicollinearity for a given term; VIF for the intercept is not meaningful and is included only for completeness._

## Interpretation notes

- **The legacy-TLS coefficient sign-flips relative to the raw univariate figure, and this is a real confounding effect worth stating plainly, not an artifact.** Section 4.10 noted that PQ-default domains are *disproportionately* likely to still accept TLS 1.0/1.1 raw: 77.8% of legacy-TLS-accepting domains are PQ-default vs. 44.4% of non-legacy-accepting ones. Once provider is controlled for, the direction reverses (OR well under 1 above). The reason: Google (89.1% legacy-TLS acceptance rate, ~99% PQ-default regardless) and Cloudflare (76.6% legacy-TLS acceptance, also overwhelmingly PQ-default) dominate the legacy-accepting population and drag the raw correlation positive. **Within the "Other/unidentified" bucket alone** (ordinary/unbranded hosting, 79.8% of the corpus), the relationship is strongly negative: only 3.5% of legacy-TLS-accepting domains there are PQ-default, vs. 41.9% of non-legacy-accepting ones -- the intuitive "weaker security posture, no PQC" pattern, masked in the raw numbers by two large platforms' blanket behavior. This is exactly the kind of finding provider-as-confound-control is supposed to surface, and is a genuinely new result, not a restatement of Section 4.10's bivariate observation.
- Beyond that reversal, this model answers whether the named predictors correlate with PQ-default status **within this live, cross-sectional sample** -- it is not a causal claim, and (as with `d1_sector_summary.py`'s bivariate cert-trust finding) the likeliest reading for the remaining associations is that both modern PQ support and clean legacy-protocol/cert-hygiene posture come from the same underlying cause (a modernized hosting stack), rather than one causing the other.
- The three terms affected by near-separation (`accepts_sslv3`, `cert_key_tier == below_112`, `provider == Microsoft/Outlook`) have wide confidence intervals and are not statistically significant (p > 0.05) -- this correctly reflects genuine uncertainty from very small cell counts (26, 16, and 5 domains respectively), not a claim that these factors don't matter. Do not quote these three odds ratios as precise point estimates in the paper; report them as inconclusive at this sample size, consistent with the project's MIN_N convention.
- The provider confound's reference level, "Other/unidentified", covers 6138 of 7,737 analytic-sample domains -- a large, heterogeneous bucket (both small/unmatched providers and domains the provider-matching logic never identified at all, Section 4.15). The provider coefficients above should be read as "vs. this mixed bucket", not "vs. the general population of other named hosts".
- Do not compare this item's odds ratios to the earlier bivariate finding's percentages directly (96.3% vs 55.0% cert-TRUSTED-by-PQ-status, Section 4.15) -- they measure different things (certificate trust/validity vs. key-strength tier) and are not meant to replicate each other.
