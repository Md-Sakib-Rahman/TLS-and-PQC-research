# Phase D sector summary (from `data/measurement/processed/phase_d_joined.csv`, 7999 live domains, 1861 distinct IPs)

## Sector overview (PQ-default / cert-trusted / accepts-SSLv3, domain% / server%)

| category | domains | servers | pq_default | cert_trusted | accepts_sslv3 |
|---|---|---|---|---|---|
| banking | 47 | 33 | 25.5% / 30.3% | 80.9% / 83.3% | 0.0% / 0.0% |
| commercial | 814 | 635 | 62.2% / 64.1% | 92.9% / 93.2% | 0.0% / 0.0% |
| defence | 13 | 7 | 0/13 | 12/13 | 1/13 |
| government | 1960 | 341 | 16.6% / 46.7% | 43.3% / 84.7% | 0.3% / 0.9% |
| telecom | 10 | 7 | 0/10 | 5/10 | 4/10 |
| unclassified | 147 | 115 | 42.2% / 47.0% | 82.2% / 89.5% | 0.7% / 0.9% |
| university | 5008 | 806 | 59.5% / 45.3% | 85.3% / 85.4% | 0.3% / 1.3% |
| ALL | 7999 | 1861 | 48.6% / 50.9% | 75.5% / 88.1% | 0.3% / 0.9% |

## Provider-group breakdown (6381 of 7999 domains have no provider match; a long tail of unidentified/smaller providers is not individually broken out)

| provider | domains | servers | pq_default |
|---|---|---|---|
| Google | 1060 | 510 | 99.1% / 98.2% |
| cPanel-style shared hosting | 423 | 92 | 59.3% / 38.0% |
| Cloudflare | 107 | 60 | 99.1% / 98.3% |
| Amazon/AWS | 21 | 17 | 12/21 |
| Microsoft/Outlook | 7 | 4 | 0/7 |

## Certificate trust by PQ adoption (not formally tested for causation)

| pq_default | domains | servers | cert_trusted |
|---|---|---|---|
| False | 3943 | 876 | 55.0% / 77.7% |
| True | 3884 | 959 | 96.3% / 97.6% |