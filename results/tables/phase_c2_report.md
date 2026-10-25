# Phase C2: legacy cipher / protocol vulnerability inference (`run_2026-09-19`)

- Live domains 7999. Cells: per-domain % / per-server %.
- **SSLv3 / POODLE and 3DES were measured by c2b** with a separate OpenSSL 1.1.1w build (the main scanner cannot offer them). SSLv3 is probed once per IP because it carries no hostname; 3DES once per domain. A server is POODLE-exposed when it accepts SSLv3 with a CBC cipher. 3DES is reported as *accepts 3DES when offered*, not as 'Sweet32-vulnerable'.
- Coverage: SSLv3 answered for 7962 of 7999 domains, 3DES for 7959; the rest were inconclusive or deferred (unreachable at scan time) and are excluded from denominators, not counted as 'no'.
- **POODLE over TLS** (broken TLS padding checks) was not tested: it needs records with corrupted padding.
- **Heartbleed is out of scope by project rule** (it extracts server memory: active exploitation).
- Duplicate tls records resolved by latest timestamp: 0.
- 1371 of 7999 domains have a cipher from the independent TLS 1.0/1.1-only probe (the rest never completed that connection).

## By sector

| group | domains | servers | Lucky13/BEAST (TLS 1.0/1.1 CBC) | IDEA negotiated (only Sweet32-class cipher the main scanner can see) | Accepts SSLv3 (per IP) | POODLE-exposed (SSLv3 + CBC) | Accepts 3DES when offered |
|---|---|---|---|---|---|---|---|
| university | 5008 | 806 | 100.0 / 100.0 | 0.0 / 0.0 | 0.3 / 1.3 | 0.3 / 1.3 | 2.2 / 5.4 |
| government | 1960 | 341 | 100.0 / 100.0 | 0.0 / 0.0 | 0.3 / 0.9 | 0.3 / 0.9 | 1.8 / 8.0 |
| commercial | 814 | 635 | 100.0 / 100.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 3.5 / 3.8 |
| unclassified | 147 | 115 | 100.0 / 100.0 | 0.0 / 0.0 | 0.7 / 0.9 | 0.7 / 0.9 | 2.8 / 3.6 |
| banking | 47 | 33 | 11/11 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 2.2 / 3.1 |
| defence | 13 | 7 | 7/7 | 0/13 | 1/13 | 1/13 | 1/13 |
| telecom | 10 | 7 | 6/6 | 0/10 | 4/10 | 4/10 | 4/10 |
| ALL | 7999 | 1861 | 100.0 / 100.0 | 0.0 / 0.0 | 0.3 / 0.9 | 0.3 / 0.9 | 2.3 / 5.4 |

## By verification tier

| group | domains | servers | Lucky13/BEAST (TLS 1.0/1.1 CBC) | IDEA negotiated (only Sweet32-class cipher the main scanner can see) | Accepts SSLv3 (per IP) | POODLE-exposed (SSLv3 + CBC) | Accepts 3DES when offered |
|---|---|---|---|---|---|---|---|
| verified | 5739 | 642 | 100.0 / 100.0 | 0.0 / 0.0 | 0.3 / 1.9 | 0.3 / 1.9 | 1.9 / 7.1 |
| unverified | 2257 | 1280 | 100.0 / 100.0 | 0.0 / 0.0 | 0.4 / 0.3 | 0.4 / 0.3 | 3.3 / 4.4 |
| rejected | 3 | 2 | – | 0/3 | 0/3 | 0/3 | 0/3 |
| ALL | 7999 | 1861 | 100.0 / 100.0 | 0.0 / 0.0 | 0.3 / 0.9 | 0.3 / 0.9 | 2.3 / 5.4 |

## Excluding service hostnames (1006 removed)

| group | domains | servers | Lucky13/BEAST (TLS 1.0/1.1 CBC) | IDEA negotiated (only Sweet32-class cipher the main scanner can see) | Accepts SSLv3 (per IP) | POODLE-exposed (SSLv3 + CBC) | Accepts 3DES when offered |
|---|---|---|---|---|---|---|---|
| university | 4255 | 784 | 100.0 / 100.0 | 0.0 / 0.0 | 0.4 / 1.3 | 0.4 / 1.3 | 2.5 / 5.4 |
| government | 1728 | 317 | 100.0 / 100.0 | 0.0 / 0.0 | 0.3 / 1.0 | 0.3 / 1.0 | 1.9 / 8.0 |
| commercial | 803 | 628 | 100.0 / 100.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 3.4 / 3.7 |
| unclassified | 146 | 114 | 100.0 / 100.0 | 0.0 / 0.0 | 0.7 / 0.9 | 0.7 / 0.9 | 2.8 / 3.6 |
| banking | 40 | 28 | 7/7 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 2.6 / 3.7 |
| defence | 13 | 7 | 7/7 | 0/13 | 1/13 | 1/13 | 1/13 |
| telecom | 8 | 6 | 6/6 | 0/8 | 4/8 | 4/8 | 4/8 |
| ALL | 6993 | 1808 | 100.0 / 100.0 | 0.0 / 0.0 | 0.4 / 0.9 | 0.4 / 0.9 | 2.5 / 5.4 |

## Most common negotiated ciphers, primary handshake (domain counts)

| cipher | domains | IDEA? |
|---|---|---|
| TLS_AES_256_GCM_SHA384 | 7178 |  |
| ECDHE-RSA-AES256-GCM-SHA384 | 294 |  |
| TLS_AES_128_GCM_SHA256 | 222 |  |
| ECDHE-RSA-AES128-GCM-SHA256 | 58 |  |
| ECDHE-ECDSA-AES256-GCM-SHA384 | 18 |  |
| TLS_CHACHA20_POLY1305_SHA256 | 18 |  |
| ECDHE-ECDSA-CHACHA20-POLY1305 | 11 |  |
| ECDHE-ECDSA-AES128-GCM-SHA256 | 10 |  |
| ECDHE-RSA-AES256-SHA384 | 8 |  |
| AES128-SHA | 4 |  |

## Most common ciphers, TLS 1.0/1.1-only probe (domain counts)

| cipher | domains | CBC-mode? |
|---|---|---|
| ECDHE-ECDSA-AES128-SHA | 874 | yes |
| ECDHE-RSA-AES128-SHA | 280 | yes |
| ECDHE-RSA-AES256-SHA | 203 | yes |
| ECDHE-ECDSA-AES256-SHA | 9 | yes |
| AES128-SHA | 4 | yes |
| AES256-SHA | 1 | yes |
