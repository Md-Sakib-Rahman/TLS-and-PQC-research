# E2b: ECH adoption via DNS HTTPS records

(PLAN.md Section 4.17 / Section 7 Group 1 item 7)

## Question

Among domains that resolve at all, how many publish a DNS HTTPS record (RFC 9460) advertising an ECH SvcParam? How does that relate to the already-measured DNSSEC-unsigned rate (Section 4.13)?

## Sample

- Population: 9028 domains with `dns_status == "resolves"` (`data/measurement/processed/liveness_all.csv`)

## Headline result (domain-level)

- ECH present: 1013/9028 (11.2%)
- HTTPS record present, no ECH: 152/9028 (1.7%)
- AliasForm only (ECH, if any, lives at the alias target -- not followed, see module docstring): 0/9028 (0.0%)
- No HTTPS record at all: 7775/9028 (86.1%)
- ECH parse error (record present, dnspython could not parse its ECH param -- see module docstring METHOD NOTE): 0/9028 (0.0%)
- nxdomain: 31/9028 (0.3%)
- servfail: 11/9028 (0.1%)
- timeout: 46/9028 (0.5%)

## Headline result (zone-level, registered-domain)

- Zones with >=1 scanned hostname showing ECH present: 383/1834 (20.9%)
- Zone grouping: registered-domain proxy suffixes ac.bd/co.bd/com.bd/edu.bd/gov.bd/info.bd/mil.bd/net.bd/org.bd/sw.bd/tv.bd, reimplementing c3_dnssec_summary.py's documented rule -- see module docstring for how this was validated against phase_c3_zones.csv (0 mismatches across 1,834 zones).

## By sector

| Sector | N | ECH present | % | HTTPS, no ECH | % | Alias-only | % | No HTTPS record | % | Parse error | % | Other/inconclusive | % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| banking | 53 | 5 | 9.4% | 1 | 1.9% | 0 | 0.0% | 42 | 79.2% | 0 | 0.0% | 5 | 9.4% |
| commercial | 869 | 214 | 24.6% | 28 | 3.2% | 0 | 0.0% | 616 | 70.9% | 0 | 0.0% | 11 | 1.3% |
| defence | 13 | 0 | 0.0% | 0 | 0.0% | 0 | 0.0% | 13 | 100.0% | 0 | 0.0% | 0 | 0.0% |
| government | 2052 | 154 | 7.5% | 6 | 0.3% | 0 | 0.0% | 1870 | 91.1% | 0 | 0.0% | 22 | 1.1% |
| telecom | 16 | 0 | 0.0% | 0 | 0.0% | 0 | 0.0% | 16 | 100.0% | 0 | 0.0% | 0 | 0.0% |
| unclassified | 157 | 24 | 15.3% | 1 | 0.6% | 0 | 0.0% | 129 | 82.2% | 0 | 0.0% | 3 | 1.9% |
| university | 5868 | 616 | 10.5% | 116 | 2.0% | 0 | 0.0% | 5089 | 86.7% | 0 | 0.0% | 47 | 0.8% |

## By verification tier

| Tier | N | ECH present | % | HTTPS, no ECH | % | Alias-only | % | No HTTPS record | % | Parse error | % | Other/inconclusive | % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| rejected | 3 | 2 | 66.7% | 0 | 0.0% | 0 | 0.0% | 1 | 33.3% | 0 | 0.0% | 0 | 0.0% |
| unverified | 2405 | 506 | 21.0% | 42 | 1.7% | 0 | 0.0% | 1799 | 74.8% | 0 | 0.0% | 58 | 2.4% |
| verified | 6620 | 505 | 7.6% | 110 | 1.7% | 0 | 0.0% | 5975 | 90.3% | 0 | 0.0% | 30 | 0.5% |

## ECH adoption vs. DNSSEC signing status (zone-level cross-tab)

Joined against `phase_c3_zones.csv`'s per-zone DNSSEC status (Section 4.13: 96.1% of zones unsigned corpus-wide).

| Zone DNSSEC status | Zones | Zones with ECH present | % |
|---|---|---|---|
| Signed (validated + signed_no_chain) | 71 | 29 | 40.8% |
| Unsigned | 1763 | 354 | 20.1% |

_Both ECH and DNSSEC are deployment-maturity signals on the DNS side of the stack; this cross-tab is descriptive, not a claim that one causes the other -- consistent with how the project has treated every other co-occurrence finding (e.g. E2a's interpretation notes)._

## Caveats

- This measures ECH presence on the corpus hostname as queried, not the zone as a whole; a zone could have ECH on a different hostname than the one scanned here (see CAVEAT in the module docstring). Zone-level numbers above are a lower bound.
- AliasForm hostnames are not followed to their target; any ECH at the alias target is not counted here.
- `ech_parse_error` domains are excluded from both the "ECH present" and "no ECH" counts above by construction -- they are neither, per Standing Rule 9.
