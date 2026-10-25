# TLS/PQC Readiness of Bangladesh's .bd Infrastructure

## Current state (as of 2026-10-15)

Corpus construction, all four measurement phases, and both follow-on measurements are **complete and verified**. What's left is writing up the results and deciding where to submit. See `PLAN.md` for the full, authoritative history and roadmap — this file is a quick orientation, not a substitute for it.

| Stage | Status |
|---|---|
| Corpus construction (22,020 domains) | DONE |
| Phase A — DNS resolution + port-443 liveness | DONE (9,028 resolve; 7,999 live) |
| Phase B — TLS/PQC handshake + HTTP headers | DONE |
| Phase C1-C4 — cert key-strength, legacy cipher/protocol, DNSSEC, SMTP/STARTTLS | DONE |
| Phase D — sector/provider summary, baseline comparison, clustering | DONE |
| E2a — multivariate logistic regression on security posture | DONE |
| E2b — ECH adoption via DNS HTTPS records | DONE |
| Phase E — writing | PARTIAL (data analysis done; Word documents need the real numbers folded in) |
| Phase F — submission | NOT STARTED (target venue undecided) |

## Folder structure

```
bd-tls-pqc-study/
├── README.md                        <- you are here
├── requirements.txt                 <- Python deps (corpus-building + measurement + analysis)
├── .gitignore
│
├── data/
│   ├── raw/                         <- UNTOUCHED pulls, exactly as fetched. Never edit these by hand.
│   ├── interim/                     <- cleaned but not yet merged
│   ├── processed/
│   │   └── domains_master.csv       <- THE corpus, 22,020 rows: domain, source, date_added, sector, verification_note
│   └── measurement/
│       ├── input/                   <- domains_frozen_<date>.csv + .sha256 (hash-checked, read-only)
│       ├── runs/<run_id>/           <- raw/*.jsonl (append-only) + run_meta.json per scan run
│       └── processed/               <- liveness_all.csv, live_domains.csv, phase_c4_domains.csv, phase_d_joined.csv
│
├── scripts/                         <- corpus-gathering scripts, numbered 01-14
│
├── measurement/                     <- Phase A onward; separate numbering (a1, b1, c1…) from scripts/
│   ├── config.yaml
│   ├── common/                      <- corpus.py, io_utils.py, net_utils.py
│   ├── phase_a_liveness/            <- a1_resolve_dns, a2_check_port443, a3_build_live_list, a4_attrition_report, e2b_ech_resolve
│   ├── phase_b_tls/                 <- b1_tls_handshake_scan, b2_collect_http_headers, b3_parse_results
│   ├── phase_c_derived/             <- c1_keysize_compliance, c2_legacy_cipher_inference, legacy_probe, c2b_legacy_scan, c3_dnssec_summary, smtp_probe, c4_smtp_scan
│   └── phase_d_analysis/            <- d1_sector_summary, d2_baseline_comparison, d3_clustering, e2a_logistic_regression
│
├── notebooks/
│   └── Domain_Corpus_EDA.ipynb      <- verified against the 22,020-domain corpus
│
├── results/
│   ├── tables/                      <- phase_{a,b,c1,c2,c3,c4,d,e2a,e2b}_*.csv / .md report deliverables
│   └── figures/
│
├── docs/
│   ├── Research_Proposal.docx
│   ├── Reference_List.docx
│   ├── Paper_Summaries.docx
│   ├── Domain_Coverage_Tracker.xlsx
│   ├── Domain_Corpus_Progress_Report.docx/pdf
│   └── Literature_Review_and_Contributions.docx/pdf
│
├── tests/                           <- test_phase_a.py, test_phase_b*.py, test_phase_c1-c4.py
├── tools/                           <- build_legacy_openssl.sh
└── logs/
    ├── collection_log.md            <- dated corpus-gathering audit trail. NEVER rewrite retroactively — append only.
    └── measurement_log.md          <- dated measurement-phase audit trail (Phase A onward). Append only.
```

## Rules carried over from corpus construction (still apply)

1. **`data/raw/` is write-once.** Re-fetching a source gets a new dated file, never an overwrite.
2. **Every domain in `domains_master.csv` traces back to a source** via the `source` column.
3. **Log every run** — corpus-gathering runs in `logs/collection_log.md`, measurement runs in `logs/measurement_log.md`. Both are append-only historical records; see `PLAN.md` Section 6, Standing Rule 1.
4. **Raw scan output (`data/measurement/runs/*/raw/*.jsonl`) is append-only and never hand-edited.** CSVs and `.md` reports under `results/` are derived and fully regenerable from it — if one looks wrong, regenerate it, don't patch it by hand.
5. **"Inconclusive" (timeout/SERVFAIL/unreachable) is never counted as "dead"/"no."** Denominators must exclude inconclusive records in the code itself, not just in the narrative text describing a result — see `PLAN.md` Section 6, Standing Rule 9, and the Phase C4 denominator bug as the cautionary example.

## Known limitations (corpus)

**Certificate Transparency discovery false positives.** 62 contaminated rows (`bd.com`, `bd.local`, and their subdomains — an unrelated US company swept in by a loose crt.sh `Identity=` match) were identified and removed on 2026-09-17. DomCop's Top 10 Million domains list was integrated as a third discovery source on 2026-09-19 (+1,284 after junk removal). Final corpus size: **22,020 domains.** Full detail in `logs/collection_log.md`.

**Shared-hosting SAN bundling.** Some providers issue one certificate covering both a customer's genuine `.bd` domain and the provider's own unrelated wrapper domain. `03_merge_and_dedupe.py`'s existing validation already excludes these — confirmed 0 leaked into `domains_master.csv`.

## Quickstart

```bash
# --- corpus construction (already done; re-run only to reproduce from scratch) ---
cd scripts
pip install -r ../requirements.txt
bash 01_fetch_crtsh.sh
bash 02_fetch_tranco.sh
python 03_merge_and_dedupe.py
python 04_sector_tag.py
# ... see scripts/ 05-14 for sector verification and DomCop integration passes

# --- measurement pipeline (already done; re-run only to reproduce) ---
cd ../measurement
python phase_a_liveness/a1_resolve_dns.py        # DNS resolution
python phase_a_liveness/a2_check_port443.py      # port-443 liveness
python phase_a_liveness/a3_build_live_list.py    # builds liveness_all.csv / live_domains.csv
python phase_b_tls/b1_tls_handshake_scan.py       # TLS/PQC handshake scan
python phase_b_tls/b2_collect_http_headers.py
python phase_b_tls/b3_parse_results.py
python phase_c_derived/c1_keysize_compliance.py
python phase_c_derived/c2_legacy_cipher_inference.py
python phase_c_derived/c3_dnssec_summary.py
python phase_c_derived/c4_smtp_scan.py
python phase_d_analysis/d1_sector_summary.py
python phase_d_analysis/d2_baseline_comparison.py
python phase_d_analysis/d3_clustering.py
python phase_d_analysis/e2a_logistic_regression.py
python phase_a_liveness/e2b_ech_resolve.py --selftest   # offline self-test, no network
python phase_a_liveness/e2b_ech_resolve.py              # real ECH-adoption scan
```

See `PLAN.md` for what each phase found, every methodology correction made along the way, and the full list of open items before submission (Phase F).
