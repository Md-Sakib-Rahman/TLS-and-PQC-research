#!/usr/bin/env bash
# Pulls domain names observed in public Certificate Transparency logs via crt.sh's
# JSON API. Run this from your own machine -- crt.sh blocks automated fetches from
# some sandboxed/hosted environments (confirmed against Claude's own sandbox).
#
# IMPORTANT: crt.sh has two different search parameters. 'q=' is a free-text
# search field that does NOT accept '%' as a wildcard and will return HTTP 200
# with an "Unsupported use of '%'" error body if you try. The wildcard-capable
# field is 'Identity=', and it expects a LEADING DOT before the suffix
# (Identity=%.gov.bd, not Identity=%gov.bd) to mean "anything ending in
# .gov.bd". Confirmed against a live 'q=' failure on 2026-09-13 -- do not
# switch this back to 'q=' without re-testing.
#
# Output: raw JSON, one file per query, saved into data/raw/crt_sh/
# This is a RAW pull -- do not hand-edit these files. Cleaning happens in
# merge_and_dedupe.py, not here.

# NOTE: deliberately NOT using 'set -e' here -- one query failing (crt.sh is a
# free service with no uptime guarantee, and wildcard queries like %.bd can be
# slow) must not silently kill the rest of the run. Each query's success/failure
# is checked and reported individually instead.
set -uo pipefail

OUTDIR="$(dirname "$0")/../data/raw/crt_sh"
DATE_TAG="$(date +%Y-%m-%d)"
FAILED=0

mkdir -p "$OUTDIR"

fetch() {
  local suffix="$1"
  local outfile="$2"
  local outpath="${OUTDIR}/${outfile}_${DATE_TAG}.json"
  echo "Fetching %${suffix} from crt.sh ..."

  # -sS: silent but SHOW errors (the earlier -s-only version hid the real
  #      failure reason, which is why the script died with no explanation).
  # --max-time: crt.sh wildcard queries can hang; give up after 90s instead
  #      of hanging the whole run.
  # --retry: transient failures (rate limiting, brief overload) get 2 retries
  #      with a 5s backoff before we give up on this query.
  # -w: capture the HTTP status code so we can tell "empty result" apart from
  #      "server error" apart from "connection never happened".
  http_code=$(curl -sS --max-time 90 --retry 2 --retry-delay 5 \
    -w "%{http_code}" \
    -o "$outpath" \
    "https://crt.sh/?Identity=%25.${suffix}&output=json" 2>"${outpath}.err")
  curl_exit=$?

  if [ $curl_exit -ne 0 ]; then
    echo "  FAILED (curl exit code ${curl_exit}) -- see ${outfile}_${DATE_TAG}.json.err for details"
    echo "  Common causes: DNS/network issue, TLS handshake failure, or 90s timeout on a slow wildcard query."
    FAILED=$((FAILED + 1))
  elif [ "$http_code" != "200" ]; then
    echo "  FAILED -- crt.sh returned HTTP ${http_code} (not 200). Check ${outfile}_${DATE_TAG}.json for crt.sh's error page."
    FAILED=$((FAILED + 1))
  elif [ ! -s "$outpath" ]; then
    echo "  WARNING: HTTP 200 but empty response body for ${suffix} -- unusual, worth a manual retry."
    FAILED=$((FAILED + 1))
  elif ! head -c1 "$outpath" | grep -q '\['; then
    # crt.sh can return HTTP 200 with an HTML error page instead of a JSON
    # array (this is exactly how the 'q=' vs 'Identity=' bug surfaced --
    # curl saw "success", the body was an error). Catch that here instead of
    # silently reporting "0 records found".
    echo "  FAILED -- HTTP 200 but response is not a JSON array (crt.sh returned an error page instead)."
    echo "  First 150 chars of response:"
    head -c 150 "$outpath" | sed 's/^/    /'
    echo ""
    FAILED=$((FAILED + 1))
  else
    count=$(grep -o '"name_value"' "$outpath" | wc -l)
    echo "  OK -- ${count} certificate records saved to ${outfile}_${DATE_TAG}.json"
    rm -f "${outpath}.err"  # no error to keep if it worked
  fi
  sleep 3  # be polite -- crt.sh is a free public service, no API key
}

fetch "gov.bd" "gov_bd"
fetch "com.bd" "com_bd"
fetch "edu.bd" "edu_bd"
fetch "ac.bd"  "ac_bd"
fetch "bd"     "all_bd"

echo ""
if [ "$FAILED" -gt 0 ]; then
  echo "${FAILED} of 5 queries failed. Check the .err files in ${OUTDIR} before running merge_and_dedupe.py."
  echo "If ALL 5 failed with the same error, run the single-query diagnostic below to isolate it."
  echo "Check the response BODY, not just the connection -- crt.sh returns HTTP 200 even on a"
  echo "malformed query, with the real error inside the HTML:"
  echo '  curl -v --max-time 30 "https://crt.sh/?Identity=%25.gov.bd&output=json" 2>&1 | tail -40'
else
  echo "All 5 queries succeeded."
fi
echo ""
echo "Log this run in logs/collection_log.md:"
echo "  Date: ${DATE_TAG} | Script: fetch_crtsh.sh | Succeeded: $((5 - FAILED))/5"
