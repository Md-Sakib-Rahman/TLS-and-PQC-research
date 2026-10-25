# Phase D baseline comparison (this study's figures computed from `data/measurement/processed/phase_d_joined.csv`, 7999 live domains; reference figures are external, cited in PLAN.md Appendix)

| metric | this study | base paper (India) | UK paper | global paper |
|---|---|---|---|---|
| TLS 1.3 adoption | 94.8% (7418/7827 of completed handshakes) | 52.41% | n/r | n/r |
| Hybrid PQ key-exchange adoption | HTTPS: 48.6% (3884/7999 live domains); SMTP: 41.0% (966/2354 of completed STARTTLS handshakes) / 36.7% (966/2633 of all domains with a usable MX record) | 49.3% | 44.0% (HTTPS) / 6.4% (SMTP) | n/r |
| PQ certificate signatures in use | 0.0% (0/7827 certificates presented) | 0% | n/r | n/r |
| Share of PQ adopters using X25519MLKEM768 | 100.0% (3884/3884 PQ-adopting domains) | n/r | n/r | ~universal convergence on X25519MLKEM768 (described, not a single %) |
| Fraction of PQ adoption attributable to infrastructure provider | descriptive only -- see phase_d_provider_breakdown.csv; no regression run (Group 3 of PLAN.md Section 7, deliberately not replicated) | n/r | provider AUC 0.957-0.994 vs sector AUC 0.156-0.573 (regression) | 93.92% |
| DNSSEC chain validation | 0.8% (14/1782 zones, approximate -- see Phase C3) | n/r (not measured) | n/r (not measured) | n/r (not measured) |
| Legacy-protocol / cipher exposure (SSLv3, POODLE, 3DES, etc.) | SSLv3 0.3% (26/7999 domains), 3DES-when-offered 2.3% (183/7959 domains probed) | n/r | n/r | measured via cipher-suite inspection (POODLE/SWEET32/FREAK/BEAST/Lucky13/RC4/LOGJAM/BREACH); no single summary % given |

'n/r' = not reported by that paper, or not directly comparable (different methodology, different metric, or not measured at all).
SMTP figure reads 'of completed STARTTLS handshakes / of all domains with a usable MX record' -- two different denominators, shown both ways because the UK paper's own 6.4% SMTP figure's exact denominator convention isn't restated here from memory. This was a stated gap until 2026-10-15, when smtp_probe.py/c4_smtp_scan.py were patched to capture the negotiated TLS group over STARTTLS (previously only TLS version/cipher were recorded).