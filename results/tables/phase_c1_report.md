# Phase C1: certificate key strength (`run_2026-09-19`)

- Live domains 7999; with a certificate 7827. Cells: per-domain % / per-server %.
- Strength tiers: NIST SP 800-57 Pt 1 Rev 5. `< 112` not acceptable for new signatures; `112` acceptable until 2030.
- NIST IR 8547 (draft, not final) proposes deprecating all RSA/ECC signatures after 2030 and disallowing them after 2035.
- Duplicate tls records resolved by latest timestamp: 0.

## By sector

| group | domains | servers | leaf < 112-bit | leaf = 112-bit (until 2030) | leaf >= 128-bit | chain < 112-bit | SHA-1/MD5 signed | PQ signature |
|---|---|---|---|---|---|---|---|---|
| university | 5008 | 806 | 0.2 / 0.1 | 74.5 / 45.0 | 25.3 / 54.9 | 0.2 / 0.1 | 0.2 / 0.1 | 0.0 / 0.0 |
| government | 1960 | 341 | 0.4 / 0.3 | 80.9 / 56.9 | 18.7 / 42.7 | 0.4 / 0.3 | 0.0 / 0.0 | 0.0 / 0.0 |
| commercial | 814 | 635 | 0.0 / 0.0 | 48.3 / 44.5 | 51.7 / 55.5 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| unclassified | 147 | 115 | 0.0 / 0.0 | 63.0 / 60.9 | 37.0 / 39.1 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| banking | 47 | 33 | 0.0 / 0.0 | 74.5 / 68.2 | 25.5 / 31.8 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| defence | 13 | 7 | 0/13 | 11/13 | 2/13 | 0/13 | 0/13 | 0/13 |
| telecom | 10 | 7 | 0/10 | 10/10 | 0/10 | 0/10 | 0/10 | 0/10 |
| ALL | 7999 | 1861 | 0.2 / 0.1 | 73.2 / 47.1 | 26.6 / 52.8 | 0.2 / 0.1 | 0.1 / 0.1 | 0.0 / 0.0 |

## By verification tier

| group | domains | servers | leaf < 112-bit | leaf = 112-bit (until 2030) | leaf >= 128-bit | chain < 112-bit | SHA-1/MD5 signed | PQ signature |
|---|---|---|---|---|---|---|---|---|
| verified | 5739 | 642 | 0.3 / 0.4 | 77.9 / 47.7 | 21.8 / 51.8 | 0.3 / 0.4 | 0.2 / 0.2 | 0.0 / 0.0 |
| unverified | 2257 | 1280 | 0.0 / 0.0 | 61.4 / 48.3 | 38.6 / 51.7 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| rejected | 3 | 2 | 0/3 | 2/3 | 1/3 | 0/3 | 0/3 | 0/3 |
| ALL | 7999 | 1861 | 0.2 / 0.1 | 73.2 / 47.1 | 26.6 / 52.8 | 0.2 / 0.1 | 0.1 / 0.1 | 0.0 / 0.0 |

## Excluding service hostnames (1006 removed)

| group | domains | servers | leaf < 112-bit | leaf = 112-bit (until 2030) | leaf >= 128-bit | chain < 112-bit | SHA-1/MD5 signed | PQ signature |
|---|---|---|---|---|---|---|---|---|
| university | 4255 | 784 | 0.2 / 0.1 | 73.3 / 44.4 | 26.5 / 55.4 | 0.2 / 0.1 | 0.2 / 0.1 | 0.0 / 0.0 |
| government | 1728 | 317 | 0.2 / 0.2 | 80.1 / 55.9 | 19.6 / 43.9 | 0.2 / 0.2 | 0.0 / 0.0 | 0.0 / 0.0 |
| commercial | 803 | 628 | 0.0 / 0.0 | 47.7 / 44.1 | 52.3 / 55.9 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| unclassified | 146 | 114 | 0.0 / 0.0 | 63.4 / 61.4 | 36.6 / 38.6 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| banking | 40 | 28 | 0.0 / 0.0 | 70.0 / 62.5 | 30.0 / 37.5 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| defence | 13 | 7 | 0/13 | 11/13 | 2/13 | 0/13 | 0/13 | 0/13 |
| telecom | 8 | 6 | 0/8 | 8/8 | 0/8 | 0/8 | 0/8 | 0/8 |
| ALL | 6993 | 1808 | 0.2 / 0.1 | 71.8 / 46.4 | 28.0 / 53.5 | 0.2 / 0.1 | 0.1 / 0.1 | 0.0 / 0.0 |

## Leaf key type x strength (domain counts)

| key type | strength (bits) | domains |
|---|---|---|
| RSA | 112 | 5732 |
| EC | 128 | 1684 |
| RSA | 128 | 343 |
| EC | 192 | 52 |
| RSA | 80 | 16 |

## Leaf signature algorithms (domain counts)

| algorithm | domains |
|---|---|
| sha256WithRSAEncryption | 6095 |
| ecdsa-with-SHA256 | 1029 |
| ecdsa-with-SHA384 | 685 |
| md5WithRSAEncryption | 9 |
| sha384WithRSAEncryption | 5 |
| sha512WithRSAEncryption | 4 |
