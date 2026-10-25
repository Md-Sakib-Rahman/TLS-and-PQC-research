# Phase C3: DNSSEC summary (run_2026-09-19)

- Source: AD flag from public validating resolvers (1.1.1.1, 8.8.8.8), recorded by a1. 9028 names resolved; 7999 of them are live (Phase B set).
- Registered-domain proxy suffixes used: ac.bd, co.bd, com.bd, edu.bd, gov.bd, info.bd, mil.bd, net.bd, org.bd, sw.bd, tv.bd. Zone counts are approximate.
- AD = False means unsigned, island of security, or unsupported algorithm. It does NOT mean broken: broken signatures give SERVFAIL, so those names are in Phase A's inconclusive bucket and are not counted here.
- `unsigned` includes zones whose apex is not in the corpus: a lower bound on signing, not proof of absence.
- *mixed = zones where some but not all names validated.

## All resolving names, by sector

| group | names | names validated | zones | zones validated | signed, no chain | unsigned | mixed* |
|---|---|---|---|---|---|---|---|
| university | 5868 | 80 (1.4%) | 452 | 3 (0.7%) | 5 (1.1%) | 444 (98.2%) | 2 |
| government | 2052 | 15 (0.7%) | 611 | 5 (0.8%) | 17 (2.8%) | 589 (96.4%) | 0 |
| commercial | 869 | 7 (0.8%) | 625 | 5 (0.8%) | 30 (4.8%) | 590 (94.4%) | 0 |
| unclassified | 157 | 0 (0.0%) | 121 | 0 (0.0%) | 4 (3.3%) | 117 (96.7%) | 0 |
| banking | 53 | 4 (7.5%) | 19 | 1 (5.3%) | 1 (5.3%) | 17 (89.5%) | 0 |
| telecom | 16 | 0 (0.0%) | 3 | 0 (0.0%) | 0 (0.0%) | 3 (100.0%) | 0 |
| defence | 13 | 0 (0.0%) | 3 | 0 (0.0%) | 0 (0.0%) | 3 (100.0%) | 0 |
| ALL | 9028 | 106 (1.2%) | 1834 | 14 (0.8%) | 57 (3.1%) | 1763 (96.1%) | 2 |

## All resolving names, by verification tier

| group | names | names validated | zones | zones validated | signed, no chain | unsigned | mixed* |
|---|---|---|---|---|---|---|---|
| verified | 6620 | 81 (1.2%) | 514 | 5 (1.0%) | 9 (1.8%) | 500 (97.3%) | 2 |
| unverified | 2405 | 25 (1.0%) | 1318 | 9 (0.7%) | 48 (3.6%) | 1261 (95.7%) | 0 |
| rejected | 3 | 0 (0.0%) | 2 | 0 (0.0%) | 0 (0.0%) | 2 (100.0%) | 0 |
| ALL | 9028 | 106 (1.2%) | 1834 | 14 (0.8%) | 57 (3.1%) | 1763 (96.1%) | 2 |

## Live names (Phase B set), by sector

| group | names | names validated | zones | zones validated | signed, no chain | unsigned | mixed* |
|---|---|---|---|---|---|---|---|
| university | 5008 | 62 (1.2%) | 448 | 3 (0.7%) | 5 (1.1%) | 440 (98.2%) | 2 |
| government | 1960 | 14 (0.7%) | 601 | 5 (0.8%) | 17 (2.8%) | 579 (96.3%) | 0 |
| commercial | 814 | 7 (0.9%) | 594 | 5 (0.8%) | 28 (4.7%) | 561 (94.4%) | 0 |
| unclassified | 147 | 0 (0.0%) | 114 | 0 (0.0%) | 4 (3.5%) | 110 (96.5%) | 0 |
| banking | 47 | 3 (6.4%) | 19 | 1 (5.3%) | 1 (5.3%) | 17 (89.5%) | 0 |
| defence | 13 | 0 (0.0%) | 3 | 0 (0.0%) | 0 (0.0%) | 3 (100.0%) | 0 |
| telecom | 10 | 0 (0.0%) | 3 | 0 (0.0%) | 0 (0.0%) | 3 (100.0%) | 0 |
| ALL | 7999 | 86 (1.1%) | 1782 | 14 (0.8%) | 55 (3.1%) | 1713 (96.1%) | 2 |

## Largest zones by number of names

| registered domain | names | validated | status |
|---|---|---|---|
| buet.ac.bd | 576 | 0 | unsigned |
| pstu.ac.bd | 219 | 0 | signed_no_chain |
| jnu.ac.bd | 210 | 0 | unsigned |
| ruet.ac.bd | 161 | 0 | unsigned |
| bubt.edu.bd | 156 | 0 | unsigned |
| green.edu.bd | 142 | 0 | unsigned |
| bau.edu.bd | 141 | 0 | signed_no_chain |
| mbstu.ac.bd | 121 | 0 | unsigned |
| butex.edu.bd | 120 | 0 | unsigned |
| brur.ac.bd | 119 | 0 | unsigned |
