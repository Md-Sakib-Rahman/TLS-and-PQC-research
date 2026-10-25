# Phase C4: SMTP/STARTTLS (run_2026-09-19)

- 2633 domains have a usable MX record (independent of HTTPS liveness), on 874 unique mail servers. Cells: n/den (per-domain % / per-server %).
- Scope note: this set includes mail-only domains (no live website) that b1/b2/b3 never scanned.
- No email is composed or sent: banner + EHLO + STARTTLS + TLS handshake + QUIT only.
- A server's reverse-DNS (PTR) check against our connecting IP is outside this tool's control; a rejection for that reason looks like `smtp_error` and is a stated limitation, not necessarily a missing feature.
- **STARTTLS-offered denominator (fixed 2026-10-15):** only domains where `starttls_offered` is not None count -- i.e. EHLO was actually read, whatever happened afterward (this includes `starttls_rejected` domains, where STARTTLS was confirmed advertised but the subsequent negotiation failed). Every connection-level failure status (connect_timeout, timeout, resolve_failed, connect_refused, closed, smtp_error) never got that far and is excluded rather than silently treated as "not offered" (Standing Rule 9). The TLS-handshake-completed metric is unaffected -- its own denominator was already just the domains where STARTTLS was offered.
- Status breakdown: {'connect_timeout': 96, 'ok': 2354, 'resolve_failed': 52, 'starttls_rejected': 51, 'no_starttls': 5, 'smtp_error': 14, 'connect_refused': 7, 'closed': 50, 'timeout': 4}

## By sector

| group | domains | mx hosts | STARTTLS offered | TLS handshake completed (of offered) |
|---|---|---|---|---|
| university | 1443 | 369 | 1329/1329 (100.0% / 100.0%) | 1320/1329 (99.3% / 99.7%) |
| commercial | 568 | 321 | 511/514 (99.4% / 98.9%) | 476/511 (93.2% / 99.3%) |
| government | 501 | 131 | 464/464 (100.0% / 100.0%) | 458/464 (98.7% / 99.1%) |
| unclassified | 90 | 61 | 78/79 (98.7% / 98.0%) | 77/78 (98.7% / 98.0%) |
| banking | 25 | 18 | 20/20 (100.0% / 100.0%) | 19/20 (95.0% / 93.3%) |
| defence | 4 | 3 | 2/3 (66.7% / 50.0%) | 2/2 (100.0% / 100.0%) |
| telecom | 2 | 2 | 2/2 (100.0% / 100.0%) | 2/2 (100.0% / 100.0%) |
| ALL | 2633 | 874 | 2406/2411 (99.8% / 99.3%) | 2354/2406 (97.8% / 99.7%) |

## By verification tier

| group | domains | mx hosts | STARTTLS offered | TLS handshake completed (of offered) |
|---|---|---|---|---|
| unverified | 1317 | 644 | 1195/1200 (99.6% / 99.1%) | 1149/1195 (96.2% / 99.6%) |
| verified | 1314 | 244 | 1210/1210 (100.0% / 100.0%) | 1205/1210 (99.6% / 99.5%) |
| rejected | 2 | 2 | 1/1 (100.0% / 100.0%) | 0/1 (0.0% / 0.0%) |
| ALL | 2633 | 874 | 2406/2411 (99.8% / 99.3%) | 2354/2406 (97.8% / 99.7%) |

## Largest mail servers by number of domains

| mx host | domains | status | STARTTLS | TLS version |
|---|---|---|---|---|
| aspmx.l.google.com | 754 | ok | True | TLSv1.3 |
| lbmx.bcc.gov.bd | 226 | ok | True | TLSv1.3 |
| smtp.google.com | 111 | ok | True | TLSv1.3 |
| mx1-hosting.jellyfish.systems | 59 | ok | True | TLSv1.3 |
| mx1.hostinger.com | 51 | starttls_rejected | True |  |
| mx.zoho.com | 44 | ok | True | TLSv1.3 |
| mail.iu.ac.bd | 44 | closed |  |  |
| mxgw.bcc.gov.bd | 14 | ok | True | TLSv1.3 |
| mx1.titan.email | 14 | ok | True | TLSv1.2 |
| route3.mx.cloudflare.net | 9 | ok | True | TLSv1.2 |
