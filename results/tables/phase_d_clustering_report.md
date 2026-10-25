# Phase D clustering: TLS/PQC configuration profiles (`data/measurement/processed/phase_d_joined.csv`, 7999 live domains)

Only **99 distinct binary profiles** actually occur (of 1024 combinatorially possible) -- see `phase_d_distinct_profiles.csv` for the full raw list. Because the data is this discrete, silhouette score never peaks as k grows (checked up to k=19: 0.44 -> 0.87, monotonic) -- so k is chosen by the elbow in INERTIA instead (chosen k=12). See the module docstring for why.

| k | silhouette (reference only) | inertia |
|---|---|---|
| 2 | 0.4422 | 62118.4 |
| 3 | 0.4189 | 52015.6 |
| 4 | 0.4305 | 41742.9 |
| 5 | 0.4365 | 34732.8 |
| 6 | 0.472 | 27257.6 |
| 7 | 0.5019 | 20730.6 |
| 8 | 0.5514 | 16642.9 |
| 9 | 0.6055 | 13999.1 |
| 10 | 0.6678 | 11876.0 |
| 11 | 0.7283 | 10044.7 |
| 12 *elbow* | 0.7474 | 8861.1 |
| 13 | 0.7628 | 8268.9 |
| 14 | 0.7974 | 7479.1 |
| 15 | 0.7925 | 6844.9 |
| 16 | 0.8056 | 6200.5 |
| 17 | 0.8289 | 5659.7 |
| 18 | 0.8394 | 5203.6 |
| 19 | 0.8675 | 4441.0 |
| 20 | 0.8827 | 4103.7 |

## 12 cluster profiles (mean of each binary feature, 0.0-1.0; sector/tier shown for description only, never used as a clustering input)

| cluster | n | % of corpus | pq_default | tls13 | cert_trusted | cert_strong_key | accepts_legacy_tls | accepts_sslv3 | accepts_3des | dnssec_validated | hsts_present | waf_detected | top sectors | top tiers |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2 | 2080 | 26.0% | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.01 | university=87.8%; commercial=6.2%; government=5.0% | verified=80.6%; unverified=19.4% |
| 6 | 1123 | 14.0% | 0.0 | 1.0 | 1.0 | 0.0 | 0.06 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | university=70.8%; government=13.8%; commercial=11.7% | verified=61.4%; unverified=38.6% |
| 7 | 900 | 11.3% | 0.01 | 1.0 | 0.0 | 0.19 | 0.03 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 | government=90.0%; university=8.0%; unclassified=0.9% | verified=90.7%; unverified=9.3% |
| 0 | 848 | 10.6% | 0.14 | 1.0 | 0.0 | 0.05 | 0.04 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | university=63.3%; government=30.3%; commercial=4.5% | verified=80.9%; unverified=19.1% |
| 1 | 762 | 9.5% | 1.0 | 1.0 | 1.0 | 1.0 | 0.94 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | university=58.7%; commercial=23.6%; government=14.3% | unverified=54.5%; verified=45.5% |
| 10 | 635 | 7.9% | 0.28 | 1.0 | 1.0 | 0.09 | 0.01 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 | government=54.0%; university=34.8%; commercial=6.5% | verified=72.3%; unverified=27.4% |
| 9 | 607 | 7.6% | 0.62 | 1.0 | 0.97 | 1.0 | 0.06 | 0.0 | 0.0 | 0.0 | 0.09 | 0.0 | university=69.2%; commercial=19.9%; government=7.6% | verified=63.3%; unverified=36.6% |
| 3 | 466 | 5.8% | 0.0 | 0.0 | 0.46 | 0.08 | 0.11 | 0.0 | 0.0 | 0.0 | 0.16 | 0.0 | university=70.4%; commercial=12.2%; government=10.7% | verified=69.5%; unverified=30.5% |
| 11 | 313 | 3.9% | 0.99 | 0.99 | 1.0 | 0.96 | 0.77 | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 | university=61.7%; commercial=24.0%; government=12.1% | verified=60.4%; unverified=39.6% |
| 8 | 154 | 1.9% | 0.22 | 0.53 | 0.75 | 0.4 | 0.92 | 0.0 | 1.0 | 0.0 | 0.12 | 0.01 | university=59.7%; government=19.5%; commercial=18.2% | verified=57.8%; unverified=42.2% |
| 5 | 85 | 1.1% | 0.25 | 0.88 | 0.82 | 0.41 | 0.16 | 0.0 | 0.04 | 1.0 | 0.27 | 0.15 | university=71.8%; government=16.5%; commercial=8.2% | verified=74.1%; unverified=25.9% |
| 4 | 26 | 0.3% | 0.0 | 0.0 | 0.31 | 0.15 | 1.0 | 1.0 | 1.0 | 0.04 | 0.04 | 0.0 | university=57.7%; government=19.2%; telecom=15.4% | verified=61.5%; unverified=38.5% |