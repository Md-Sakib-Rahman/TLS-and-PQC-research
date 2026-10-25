# Phase A attrition report

- Run: `run_2026-09-19`
- Corpus file: `domains_frozen_2026-09-19.csv` (sha256 `203d26072386c38ad54f71d32e2b7155dd7f363377429f3dff37f577f9cbf00e`)
- Vantage point: Chattogram, Bangladesh; residential broadband (ISP not disclosed)
- Resolvers: 1.1.1.1, 8.8.8.8

Percent columns use scanned domains as the denominator, except `open_pct_of_resolving`. `inconclusive` (timeout/SERVFAIL) is NOT counted as dead.

## By sector category

| group | corpus_total | scanned | resolves | resolves_pct | nxdomain | no_address | inconclusive | open_443 | open_443_pct | open_pct_of_resolving | closed | no_response |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| university | 16104 | 16104 | 5868 | 36.4 | 8756 | 762 | 718 | 5008 | 31.1 | 85.3 | 251 | 609 |
| government | 3999 | 3999 | 2052 | 51.3 | 1302 | 14 | 631 | 1960 | 49.0 | 95.5 | 18 | 74 |
| commercial | 1561 | 1561 | 869 | 55.7 | 605 | 31 | 56 | 814 | 52.1 | 93.7 | 18 | 37 |
| unclassified | 233 | 233 | 157 | 67.4 | 63 | 5 | 8 | 147 | 63.1 | 93.6 | 2 | 8 |
| banking | 80 | 80 | 53 | 66.2 | 21 | 3 | 3 | 47 | 58.8 | 88.7 | 0 | 6 |
| telecom | 28 | 28 | 16 | 57.1 | 11 | 1 | 0 | 10 | 35.7 | 62.5 | 3 | 3 |
| defence | 15 | 15 | 13 | 86.7 | 1 | 0 | 1 | 13 | 86.7 | 100.0 | 0 | 0 |
| ALL | 22020 | 22020 | 9028 | 41.0 | 10759 | 816 | 1417 | 7999 | 36.3 | 88.6 | 292 | 737 |

## By verification tier

| group | corpus_total | scanned | resolves | resolves_pct | nxdomain | no_address | inconclusive | open_443 | open_443_pct | open_pct_of_resolving | closed | no_response |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| verified | 14706 | 14706 | 6620 | 45.0 | 6800 | 759 | 527 | 5739 | 39.0 | 86.7 | 255 | 626 |
| unverified | 7305 | 7305 | 2405 | 32.9 | 3955 | 57 | 888 | 2257 | 30.9 | 93.8 | 37 | 111 |
| rejected | 9 | 9 | 3 | 33.3 | 4 | 0 | 2 | 3 | 33.3 | 100.0 | 0 | 0 |
| ALL | 22020 | 22020 | 9028 | 41.0 | 10759 | 816 | 1417 | 7999 | 36.3 | 88.6 | 292 | 737 |
