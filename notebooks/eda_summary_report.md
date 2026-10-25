# Domain Corpus — EDA Summary

Generated from `domains_master.csv` (22,020 total rows).

## Sector composition

| Sector | Total | Verified | % Verified |
|---|---|---|---|
| university | 16,104 | 13,126 | 82% |
| government | 3,999 | 1,487 | 37% |
| commercial | 1,561 | 0 | 0% |
| unclassified | 233 | 0 | 0% |
| banking | 80 | 65 | 81% |
| telecom | 28 | 28 | 100% |
| defence | 15 | 0 | 0% |
| **Total** | **22,020** | **14,706** | **67%** |

## Data quality

- Exact duplicate domain rows: 0
- Rows with unrecognized sector format: 0
- Top suffix: `.ac.bd` (8,342 domains)

## Figures generated

- `report_figures/01_sector_counts.png` — Domain corpus composition by sector
- `report_figures/02_verification_tier_by_sector.png` — Verification confidence tier by sector
- `report_figures/03_overall_verification_pie.png` — Overall corpus verification status
- `report_figures/04_top_suffixes.png` — Top 10 domain suffixes
- `report_figures/05_source_distribution.png` — Domains by discovery source file

## Scope note

This summary describes domain *discovery and classification* only. No TLS scan has been run against this corpus; liveness, reachability, and cryptographic configuration are not covered here and are addressed in a later stage of the project.