# Collection Log

One entry per gathering run. Keep it short -- this is a provenance trail, not a diary.

Format:
```
## YYYY-MM-DD
- Script: <name>
- Source: <what was queried>
- Result: <N domains / N records>
- Notes: <rate limiting, errors, anything that looked wrong>
```

---

<!-- Add entries below this line -->

## 2026-09-13
- Script: fetch_crtsh.sh
- Source: crt.sh Identity= queries for %.gov.bd, %.com.bd, %.edu.bd, %.ac.bd, %.bd
- Result: 5/5 queries succeeded; 2372+4320+2476+3432+4760 raw certificate records
- Notes: none

## 2026-09-13
- Script: fetch_tranco.sh
- Source: tranco-list.eu top-1m.csv.zip, filtered to .bd
- Result: 683 .bd domains found
- Notes: BUG FOUND AND FIXED -- first run returned 0 .bd domains. Tranco's CSV
  has CRLF line endings, so `grep -E '\.bd$'` never matched (each line
  actually ends "...bd\r", with \r sitting between 'd' and the end-of-line
  anchor). Fixed by piping through `tr -d '\r'` before the grep filter.
  Re-ran and got the expected 683 domains (google.com.bd, daraz.com.bd,
  land.gov.bd, etc. all present in the raw file). See scripts/fetch_tranco.sh.

## 2026-09-13
- Script: merge_and_dedupe.py
- Source: data/raw/crt_sh/*.json + data/interim/tranco_bd_2026-09-13.txt (no
  sector_authority_lists files present yet -- not yet manually collected)
- Result: 8348 unique candidate domains written to data/processed/domains_master.csv
- Notes: none

## 2026-09-13
- Script: sector_tag.py
- Source: data/processed/domains_master.csv (suffix heuristics only -- 0
  authority-list mappings loaded, since data/raw/sector_authority_lists/ is
  still empty)
- Result: university (heuristic) 4170, government (heuristic) 2724,
  commercial (heuristic -- review manually) 1305, unclassified 146,
  defence (heuristic) 3
- Notes: 146 unclassified domains need manual review before scanning. All
  sector tags are heuristic-only pending manual sector authority list
  collection (Bangladesh Bank / UGC / BTRC / gov portal pulls per README).

## 2026-09-13
- Script: scripts/flag_finance_telecom.py
- Source: data/processed/domains_master.csv (commercial/unclassified pool)
- Result: 87 domains reclassified -- 57 banking (named match), 22 telecom,
  8 banking (low confidence, generic 'bank' substring). Updated breakdown:
  university 4170, government 2724, commercial 1221, unclassified 143,
  banking 57, telecom 22, banking (low confidence) 8, defence 3.
- Notes: candidate list written to data/processed/banking_telecom_review.csv
  for manual verification against bb.org.bd / btrc.gov.bd.

## 2026-09-13
- Task: manual verification of data/processed/banking_telecom_review.csv
- Source: bb.org.bd scheduled-bank directory
  (https://www.bb.org.bd/en/index.php/links/links/9), BTRC's published
  4-operator list (Teletalk, Grameenphone, Banglalink, Robi Axiata),
  Wikipedia "List of banks in Bangladesh", and targeted web searches for
  domains not resolvable from the above.
- Result: verified_against_official_list filled in for all 87 rows --
  75 Y (25 exact matches to bb.org.bd's directory, 6 confirmed via the
  institution's own site where bb.org.bd's directory was stale), 6 N
  (confirmed false positives: imagebank.com.bd x2, krishibari.com.bd x2,
  sbit.com.bd x2 -- none are financial institutions), 6 FLAGGED rather
  than guessed: abbank.com.bd x2, standardchartered.com.bd, dbbl.com.bd
  (all four -- every source found lists a DIFFERENT official domain for
  that institution, with no evidence the institution also owns the .bd
  variant in our list), citibank.com.bd (same reason), and
  grameenbank.org.bd (real institution but Wikipedia lists it as a
  NON-scheduled bank, not on bb.org.bd's scheduled directory -- sector
  categorization is a judgment call, not a domain-ownership question).
- Notes: bb.org.bd's own website-link directory is stale for several
  banks (e.g. lists dhakabankltd.com instead of dhakabank.com.bd,
  al-arafahbank.com instead of aibl.com.bd) -- do not treat a mismatch
  against that single page as proof a domain is wrong; cross-check the
  institution's own site before flagging. The 6 FLAG rows still need a
  human with WHOIS/registrant access or a phone call to bb.org.bd/the
  bank to resolve -- a domain check alone could not confirm or deny them.

## 2026-09-13
- Task: built sector authority lists and ran scripts/verify_against_source_list.py
- Sources fetched:
  - data/raw/sector_authority_lists/universities_ugc.csv -- scraped directly
    from ugc-universities.gov.bd's own public/private/international/CBHE
    tables (166 base domains). 16 institutions on UGC's own pages had no
    usable website listed (mostly not-yet-operational or under-dispute
    universities) -- excluded rather than guessed.
  - data/raw/sector_authority_lists/gov_national_portal.csv -- scraped from
    bangladesh.gov.bd's Ministries-and-Divisions directory page, which
    embeds domains for every ministry/directorate/office in its
    data-search attributes and links (939 base domains). This is NOT
    exhaustive of all government offices in Bangladesh (the portal itself
    claims 25,000+ linked sites; this one directory page surfaced 939) --
    treat "not found" as "not on this particular page," not "invalid."
  - Both fetched via curl -k (WebFetch failed with a cert-verification
    error on both bb.org.bd-style .gov.bd hosts; raw HTML was parsed
    directly with Python instead of a browser render).
- Ran: python3 verify_against_source_list.py "university (heuristic)" ../data/raw/sector_authority_lists/universities_ugc.csv
  Result: 1330 verified / 2840 not found / 0 extraction issues.
  1241 distinct unmatched base domains -- full list with per-domain
  counts written to data/processed/university_unmatched_bases.csv.
- Ran: python3 verify_against_source_list.py "government (heuristic)" ../data/raw/sector_authority_lists/gov_national_portal.csv
  Result: 451 verified / 2273 not found / 0 extraction issues.
  537 distinct unmatched base domains -- full list with per-domain
  counts written to data/processed/government_unmatched_bases.csv.
- Notes: high not-found counts are expected and NOT evidence of bad
  domains -- Bangladesh's .edu.bd/.ac.bd suffixes are used by secondary
  schools and colleges as well as UGC-listed universities (the master
  list's "university (heuristic)" tag can't tell them apart), and the
  gov_national_portal.csv source list is a partial capture, not a full
  government domain census. Spot-checked nu.ac.bd (13 domains, unmatched):
  UGC's own table lists National University's domain as nu.edu.bd, not
  nu.ac.bd -- a real discrepancy in UGC's data, not an extraction bug.

## 2026-09-17
- Task: removed the "NOT .bd ccTLD" rows identified in
  data/processed/suffix_anomaly_review.csv from domains_master.csv
- Source: data/processed/suffix_anomaly_review.csv, category "NOT .bd
  ccTLD" -- 62 domains whose actual last label is .com or .local, not
  .bd (bd.com, bd.local, and their subdomains -- traced to Becton
  Dickinson's real corporate domain, an unrelated US company swept in by
  a crt.sh Identity=%.bd wildcard-matching false positive, not a parsing
  bug in this project's own scripts).
- Result: domains_master.csv 20,800 -> 20,738 rows. Snapshotted the file
  first; byte-for-byte diff after removal confirmed exactly 62 lines
  removed, 0 lines added, every remaining row unchanged in content and
  order. The 6 "non-standard .bd suffix" rows in the same review CSV
  (.mygov.bd, .links.bd, .webapp.bd, .boardresults.bd, .codecloud.bd --
  structurally valid .bd domains with an unrecognized second-level label)
  were deliberately left untouched.
- Notes: none

## 2026-09-19
- Script: fetched DomCop's Top 10 Million domains list into
  data/raw/domcop/top10milliondomains.csv, then ran
  13_find_new_domcop_domains.py against it
- Source: DomCop top10milliondomains.csv (10,000,000 rows) compared against
  the then-current domains_master.csv (20,738 rows)
- Result: 1,793 genuine .bd domains found in DomCop's list (last label ==
  "bd", same rule as check_suffix_anomalies.py); 508 already present in the
  corpus; 1,285 genuinely new, written to
  data/processed/domcop_new_candidates.csv for manual review before
  merging.
- Notes: DomCop was brought in because the global longitudinal PQ-TLS paper
  credits it with better country-specific gov/public-sector coverage than
  Tranco. This script only reports and writes the candidate list -- nothing
  is merged into domains_master.csv here; see the junk-domain entry and the
  14_merge_domcop_candidates.py entry below for what happened next.

## 2026-09-19
- Task: junk-domain / label-count investigation of
  domcop_new_candidates.csv before merging
- Source: manual inspection of DomCop's raw rank ordering around
  domcop_new_candidates.csv's lowest-confidence entries
- Result: found a cluster of consecutive DomCop ranks (1,795,254-1,795,329)
  all sharing the identical minimum Open Page Rank score of 3.47 --
  DomCop's apparent floor score for entries with essentially no ranking
  signal. "com.google.android.gms.internal.bd" (rank 1,795,260) is not a
  domain at all -- it's a reversed-notation Android/Google-Play-Services
  internal package identifier that happens to end in ".bd" (the same
  pattern recurs for other ccTLDs in the same cluster:
  com.google.android.gms.internal.ar at rank 1,795,012, .be at 1,795,282,
  .bh.bi at 1,795,324). It passed is_genuine_bd()'s suffix check but was
  manually removed from domcop_new_candidates.csv before merging (1,285 ->
  1,284 rows).
- Notes: two more entries from the same cluster -- rec.arts.bd and
  fr.rec.arts.bd -- were NOT caught at this point and were merged into
  domains_master.csv as "unclassified" rows (see the cleanup entry at the
  end of this date for their removal once confirmed). Three other
  same-cluster entries -- 004.bd, 017.bd, and this.bd -- were reviewed and
  deliberately KEPT as genuinely ambiguous rather than confirmed junk:
  bare numeric or short generic labels under .bd are not obviously fake
  the way a Java package name or a Usenet newsgroup name is.

## 2026-09-19
- Script: 14_merge_domcop_candidates.py
- Source: data/processed/domcop_new_candidates.csv (1,284 rows, post
  junk-removal), appended into data/processed/domains_master.csv at
  suffix-heuristic confidence (the same tiers sector_tag.py uses),
  append-only
- Result: domains_master.csv 20,738 -> 22,022 rows. Snapshotted first;
  byte-for-byte diff after the merge confirmed all 1,284 new rows were
  appended with 0 skipped duplicates, and every pre-existing row was left
  unchanged in content and order. New rows by sector (heuristic,
  unverified): government (heuristic) 631, commercial (heuristic --
  review manually) 355, unclassified 160, university (heuristic) 126,
  defence (heuristic) 12.
- Notes: none of the new rows were pre-verified. The two follow-up
  verification passes below (flag_finance_telecom.py re-run, government
  re-verification) are what upgraded some of this batch.

## 2026-09-19
- Script: 05_flag_finance_telecom.py (re-run against the DomCop-merged
  batch)
- Source: data/processed/domains_master.csv commercial/unclassified pool,
  restricted to the 1,284 newly-merged domcop_top10m rows
- Result: 21 domains reclassified as banking/telecom keyword-match
  candidates (15 from "commercial (heuristic -- review manually)", 6 from
  "unclassified") -- written to data/processed/banking_telecom_review.csv
  for manual verification against bb.org.bd / btrc.gov.bd, same process as
  the original 87-domain review on 2026-09-13.
- Notes: none

## 2026-09-19
- Task: re-ran verify_against_source_list.py for "government (heuristic)"
  against both existing source lists, restricted to the 631 new
  DomCop-sourced government-heuristic candidates
- Source: data/raw/sector_authority_lists/gov_hierarchy.csv (union/upazila
  administrative hierarchy, built 2026-09-14 by clean_gov_hierarchy.py)
  and data/raw/sector_authority_lists/gov_national_portal.csv (939-domain
  national portal directory, from 2026-09-13)
- Result: 78 verified against gov_hierarchy.csv, then 297 more verified
  against gov_national_portal.csv out of the remainder -- 375 total
  upgraded to "government (institution-verified)"; 256 remain "government
  (heuristic -- not verified)". Pre-existing (non-DomCop) government-
  heuristic rows were not touched by this pass.
- Notes: separately, while reviewing the original 2026-09-13 unmatched-
  bases output (data/processed/government_unmatched_bases.csv, 537
  domains unmatched against gov_national_portal.csv that date), 14
  domains matching the "acland-*" naming pattern (Assistant
  Commissioner-Land sub-offices) were identified among that pass's
  unmatched candidates, illustrating a real government sub-office layer
  neither current source list covers. Left at heuristic confidence, not
  verified.

## 2026-09-19
- Task: found, fixed, and applied a bug in
  11_apply_banking_telecom_verification.py
- Source: data/processed/banking_telecom_review.csv's 21-row post-merge
  banking/telecom review (see the flag_finance_telecom.py entry above);
  each of the 21 domains checked against bb.org.bd's scheduled-bank
  directory / BTRC's 4-operator list, cross-checking the institution's own
  site and DNS resolution where bb.org.bd's directory looked stale (same
  process established on 2026-09-13)
- Result: BUG FOUND -- category_from_old_sector() derived the
  banking/telecom category from the row's old_sector column (always
  "commercial"/"unclassified" in this review file), not new_sector (where
  "banking"/"telecom" actually lives), so every row would have been
  mislabeled (e.g. Robi/Teletalk domains as "commercial (source-verified)"
  instead of "telecom (source-verified)"; confirmed banks as "unclassified
  (source-verified)"). Root cause: the script's own docstring correctly
  described the intended behavior, but the code read the wrong column --
  a variable-naming slip, not a logic-design error. FIXED by deriving
  category from new_sector instead. A synthetic 3-row test (banking/Y,
  telecom/Y, banking/N) confirmed the fix produced "banking
  (source-verified)", "telecom (source-verified)", and "banking (keyword
  match -- rejected, false positive)" correctly, before it was run against
  real data. Verdicts recorded: 18 Y / 3 N / 0 FLAG. Applied to
  domains_master.csv (snapshotted first; byte-for-byte diff after
  confirmed exactly 21 lines changed, sector field only, nothing else
  moved). New corpus-wide totals: banking 65 verified / 9 rejected / 6 not
  yet individually verified; telecom 28 verified.
- Notes: none

## 2026-09-19
- Task: removed 2 confirmed non-domain rows (rec.arts.bd, fr.rec.arts.bd)
  from domains_master.csv, following up on the junk-domain investigation
  logged earlier this date
- Source: manual review confirming both are Usenet Big-8
  newsgroup-hierarchy names (rec.arts.* / fr.rec.arts.* -- the same real,
  documented naming convention as rec.arts.movies / rec.arts.startrek),
  not domains -- neither resolves in DNS, and both sit in the same
  tied-floor-score DomCop rank cluster (1,795,254-1,795,329) as the
  confirmed com.google.android.gms.internal.bd Android-package junk
  already excluded from the merge.
- Result: domains_master.csv 22,022 -> 22,020 rows. Snapshotted first;
  byte-for-byte diff after removal confirmed exactly 2 lines removed, 0
  lines added, every remaining row unchanged in content and order.
- Notes: 004.bd, 017.bd, and this.bd remain from the same cluster --
  reviewed and deliberately kept as genuinely ambiguous, not confirmed
  junk. Only rec.arts.bd and fr.rec.arts.bd were new information changing
  that call.

## 2026-09-19
- Task: fixed a reintroduction bug -- re-running
  14_merge_domcop_candidates.py after the rec.arts.bd/fr.rec.arts.bd
  cleanup silently re-added both rows to domains_master.csv
- Source: data/processed/domcop_new_candidates.csv still contained both
  domains (the cleanup entry above only removed them from
  domains_master.csv, not from the candidates file that feeds the merge).
  14_merge_domcop_candidates.py's whole design is non-destructive
  "append only what's missing from domains_master.csv" -- it has no way to
  tell "never yet added" apart from "deliberately removed," so seeing
  both domains present in its input and absent from the corpus, it
  correctly-but-naively read that as "these are new" and re-added them.
- Result: fixed by removing rec.arts.bd and fr.rec.arts.bd from
  domcop_new_candidates.csv as well as re-removing them from
  domains_master.csv. Confirmed directly against the live files after the
  fix:
    tail -n +2 data/processed/domains_master.csv | grep -c "^"   -> 22020
    grep -E "^(rec\.arts\.bd|fr\.rec\.arts\.bd)," data/processed/domains_master.csv        -> (no output)
    grep -E "^(rec\.arts\.bd|fr\.rec\.arts\.bd)," data/processed/domcop_new_candidates.csv  -> (no output)
  domcop_new_candidates.csv is now 1,282 data rows (was 1,284).
- Notes: STANDING RULE for this project -- any time a domain is
  deliberately excluded from domains_master.csv, it must also be removed
  from whatever candidate/source file feeds the merge/add step that could
  reintroduce it (e.g. domcop_new_candidates.csv for
  14_merge_domcop_candidates.py, data/interim/ files for
  merge_and_dedupe.py). Deleting only the downstream row in
  domains_master.csv is not sufficient -- the next re-run of the upstream
  script will silently bring it back, because these append-only scripts
  are designed to trust their own input file as the definition of "should
  be in the corpus," not to remember past exclusions.
