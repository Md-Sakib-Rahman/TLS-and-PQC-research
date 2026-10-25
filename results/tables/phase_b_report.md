# Phase B results (`run_2026-09-19`)

- Live domains: 7999 on 1861 distinct IPs.
- Cells show **per-domain % / per-server %** (each IP counts once in total). Groups with fewer than 30 domains in the denominator show raw counts `k/n`.
- Missing data is excluded from denominators, never counted as failure (TLS `not_scanned`; HTTP `pending`).
- 1219 HTTP records came from a secondary Bangladeshi vantage point (backfill).

## TLS and post-quantum key exchange, by sector

| group | domains | servers | TLS 1.3 | PQ default | PQ capable, not default | not capable | accepts TLS 1.0/1.1 |
|---|---|---|---|---|---|---|---|
| university | 5008 | 806 | 95.1 / 93.2 | 59.5 / 45.3 | 0.0 / 0.1 | 31.8 / 41.8 | 16.0 / 28.3 |
| government | 1960 | 341 | 96.5 / 86.4 | 16.6 / 46.7 | 0.0 / 0.0 | 78.8 / 35.6 | 12.3 / 39.3 |
| commercial | 814 | 635 | 92.9 / 93.0 | 62.2 / 64.1 | 0.0 / 0.0 | 29.0 / 27.2 | 33.7 / 38.2 |
| unclassified | 147 | 115 | 89.0 / 86.8 | 42.2 / 47.0 | 0.0 / 0.0 | 46.3 / 39.1 | 24.5 / 27.8 |
| banking | 47 | 33 | 70.2 / 66.7 | 25.5 / 30.3 | 0.0 / 0.0 | 44.7 / 36.4 | 23.4 / 30.3 |
| defence | 13 | 7 | 6/13 | 0/13 | 0/13 | 6/13 | 7/13 |
| telecom | 10 | 7 | 2/10 | 0/10 | 0/10 | 0/10 | 6/10 |
| ALL | 7999 | 1861 | 94.8 / 90.6 | 48.6 / 50.9 | 0.0 / 0.1 | 43.4 / 35.7 | 17.2 / 34.8 |

## TLS and post-quantum key exchange, by verification tier

| group | domains | servers | TLS 1.3 | PQ default | PQ capable, not default | not capable | accepts TLS 1.0/1.1 |
|---|---|---|---|---|---|---|---|
| verified | 5739 | 642 | 95.5 / 88.9 | 46.4 / 33.5 | 0.0 / 0.2 | 46.1 / 48.0 | 12.1 / 23.3 |
| unverified | 2257 | 1280 | 92.9 / 91.4 | 53.9 / 59.1 | 0.0 / 0.0 | 36.6 / 30.0 | 30.2 / 39.4 |
| rejected | 3 | 2 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| ALL | 7999 | 1861 | 94.8 / 90.6 | 48.6 / 50.9 | 0.0 / 0.1 | 43.4 / 35.7 | 17.2 / 34.8 |

## Sensitivity: excluding 1006 auto-created service hostnames

Same metrics with cpanel/webmail/mail/webdisk-style hostnames removed (approximate, first-label heuristic). If a figure moves a lot between this table and the one above, service hostnames are driving it.

| group | domains | servers | TLS 1.3 | PQ default | PQ capable, not default | not capable | accepts TLS 1.0/1.1 | HSTS |
|---|---|---|---|---|---|---|---|---|
| university | 4255 | 784 | 95.1 / 93.6 | 58.4 / 46.1 | 0.0 / 0.1 | 32.9 / 41.6 | 16.5 / 28.6 | 13.0 / 15.6 |
| government | 1728 | 317 | 96.5 / 85.9 | 13.0 / 46.8 | 0.0 / 0.0 | 82.3 / 35.0 | 11.4 / 40.4 | 67.5 / 23.2 |
| commercial | 803 | 628 | 93.2 / 93.3 | 62.8 / 64.6 | 0.0 / 0.0 | 28.8 / 27.0 | 34.0 / 38.3 | 20.7 / 20.7 |
| unclassified | 146 | 114 | 89.0 / 86.7 | 42.5 / 47.4 | 0.0 / 0.0 | 45.9 / 38.6 | 24.7 / 28.1 | 20.8 / 20.3 |
| banking | 40 | 28 | 82.5 / 78.6 | 30.0 / 35.7 | 0.0 / 0.0 | 52.5 / 42.9 | 17.5 / 25.0 | 46.2 / 44.4 |
| defence | 13 | 7 | 6/13 | 0/13 | 0/13 | 6/13 | 7/13 | 6/13 |
| telecom | 8 | 6 | 0/8 | 0/8 | 0/8 | 0/8 | 6/8 | 4/8 |
| ALL | 6993 | 1808 | 94.8 / 91.0 | 47.0 / 51.7 | 0.0 / 0.1 | 45.0 / 35.5 | 17.6 / 35.1 | 28.0 / 19.1 |

## Certificates, by sector

| group | domains | servers | trusted | expired | self-signed | hostname mismatch | RSA < 2048 |
|---|---|---|---|---|---|---|---|
| university | 5008 | 806 | 85.3 / 85.4 | 4.4 / 4.7 | 1.3 / 1.7 | 11.1 / 10.0 | 0.2 / 0.3 |
| government | 1960 | 341 | 43.3 / 84.7 | 1.4 / 3.1 | 13.7 / 1.3 | 16.7 / 7.6 | 0.4 / 1.0 |
| commercial | 814 | 635 | 92.9 / 93.2 | 1.6 / 1.6 | 0.2 / 0.2 | 4.8 / 4.7 | 0.0 / 0.0 |
| unclassified | 147 | 115 | 82.2 / 89.5 | 0.7 / 0.9 | 8.2 / 2.6 | 12.3 / 7.8 | 0.0 / 0.0 |
| banking | 47 | 33 | 80.9 / 83.3 | 2.1 / 3.0 | 2.1 / 1.5 | 6.4 / 6.1 | 0.0 / 0.0 |
| defence | 13 | 7 | 12/13 | 0/13 | 0/13 | 1/13 | 0/11 |
| telecom | 10 | 7 | 5/10 | 0/10 | 0/10 | 1/10 | 0/10 |
| ALL | 7999 | 1861 | 75.5 / 88.1 | 3.3 / 3.0 | 4.4 / 1.0 | 11.8 / 7.5 | 0.3 / 0.3 |

## HTTP headers, by sector

| group | domains | servers | HTTP response | HSTS | WAF/CDN signature |
|---|---|---|---|---|---|
| university | 5008 | 806 | 96.1 / 94.0 | 11.9 / 15.2 | 13.4 / 23.2 |
| government | 1960 | 341 | 98.7 / 96.0 | 63.3 / 25.2 | 8.0 / 32.3 |
| commercial | 814 | 635 | 97.3 / 97.2 | 20.6 / 20.7 | 34.1 / 37.4 |
| unclassified | 147 | 115 | 98.6 / 98.3 | 21.4 / 21.0 | 19.3 / 22.1 |
| banking | 47 | 33 | 97.9 / 97.0 | 43.5 / 40.6 | 13.0 / 18.8 |
| defence | 13 | 7 | 13/13 | 6/13 | 0/13 |
| telecom | 10 | 7 | 10/10 | 4/10 | 0/10 |
| ALL | 7999 | 1861 | 97.0 / 95.7 | 26.1 / 19.2 | 14.2 / 30.2 |

HSTS per-domain bounds (pending domains assumed all-absent / all-present):

| group | pending | HSTS low % | HSTS high % |
|---|---|---|---|
| university | 0 | 11.9 | 11.9 |
| government | 0 | 63.3 | 63.3 |
| commercial | 0 | 20.6 | 20.6 |
| unclassified | 0 | 21.4 | 21.4 |
| banking | 0 | 43.5 | 43.5 |
| defence | 0 | 46.2 | 46.2 |
| telecom | 0 | 40.0 | 40.0 |
| ALL | 0 | 26.1 | 26.1 |

## Old-version acceptance by PQ class (domain counts)

| pq_class | accepts TLS 1.0/1.1 | refuses | no clear answer |
|---|---|---|---|
| pq_default | 1032 | 2851 | 1 |
| pq_capable_not_default | 0 | 2 | 0 |
| not_capable | 149 | 3319 | 1 |
| no_tls13 | 151 | 258 | 0 |
| unknown | 39 | 170 | 26 |

## Largest shared-hosting IPs

| ip | domains | categories | pq classes | HTTP ok | HTTP pending |
|---|---|---|---|---|---|
| 103.157.135.180 | 1219 | university=1217; unclassified=2 | pq_default=1219 | 1216 | 0 |
| 159.13.21.17 | 481 | government=481 | not_capable=481 | 481 | 0 |
| 159.13.21.95 | 245 | government=245 | not_capable=245 | 245 | 0 |
| 131.186.50.33 | 162 | government=155; unclassified=7 | not_capable=162 | 162 | 0 |
| 159.13.21.220 | 161 | government=154; unclassified=5; banking=2 | not_capable=161 | 161 | 0 |
| 103.108.140.126 | 140 | university=140 | pq_default=140 | 138 | 0 |
| 103.159.2.215 | 120 | university=120 | pq_default=120 | 120 | 0 |
| 131.186.51.242 | 101 | government=96; unclassified=5 | not_capable=101 | 101 | 0 |
| 103.134.89.234 | 98 | university=98 | not_capable=98 | 98 | 0 |
| 159.13.20.243 | 94 | government=94 | not_capable=94 | 94 | 0 |
| 203.96.189.167 | 87 | university=87 | pq_default=87 | 87 | 0 |
| 203.190.10.99 | 78 | university=76; commercial=2 | not_capable=78 | 78 | 0 |
| 103.159.2.19 | 76 | university=76 | not_capable=76 | 76 | 0 |
| 206.72.198.91 | 73 | university=73 | pq_default=73 | 73 | 0 |
| 103.28.121.122 | 68 | university=68 | no_tls13=68 | 68 | 0 |
