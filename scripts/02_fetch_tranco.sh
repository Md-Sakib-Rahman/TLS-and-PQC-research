#!/usr/bin/env bash
# Downloads the current Tranco top-sites list and filters it to .bd domains.
# Tranco publishes a new list daily at a stable "latest" URL that redirects to the
# dated file -- check https://tranco-list.eu if this URL has moved.
#
# Output: raw full list in data/raw/tranco/, filtered .bd subset in data/interim/

# Deliberately not using 'set -e' -- see fetch_crtsh.sh for why: a failed
# download should print a clear reason, not die silently.
set -uo pipefail

RAW_DIR="$(dirname "$0")/../data/raw/tranco"
INTERIM_DIR="$(dirname "$0")/../data/interim"
DATE_TAG="$(date +%Y-%m-%d)"

mkdir -p "$RAW_DIR" "$INTERIM_DIR"

ZIP_PATH="${RAW_DIR}/tranco_top1m_${DATE_TAG}.zip"
CSV_PATH="${RAW_DIR}/tranco_top1m_${DATE_TAG}.csv"

echo "Downloading Tranco list ..."
http_code=$(curl -sS -L --max-time 120 --retry 2 --retry-delay 5 \
  -w "%{http_code}" \
  -o "$ZIP_PATH" \
  "https://tranco-list.eu/top-1m.csv.zip" 2>"${ZIP_PATH}.err")
curl_exit=$?

if [ $curl_exit -ne 0 ]; then
  echo "FAILED (curl exit code ${curl_exit}) -- see ${ZIP_PATH}.err"
  echo "If this is a network/DNS issue, this single command will confirm it:"
  echo '  curl -v --max-time 30 "https://tranco-list.eu/top-1m.csv.zip" 2>&1 | tail -40'
  exit 1
fi
if [ "$http_code" != "200" ]; then
  echo "FAILED -- tranco-list.eu returned HTTP ${http_code}. The download URL may have moved --"
  echo "check https://tranco-list.eu directly for the current 'top-1m.csv.zip' link."
  exit 1
fi
rm -f "${ZIP_PATH}.err"

echo "Extracting ..."
if ! unzip -p "$ZIP_PATH" > "$CSV_PATH" 2>/tmp/tranco_unzip_err; then
  echo "FAILED to extract ${ZIP_PATH} -- it may be an HTML error page, not a real zip."
  echo "First few lines of what was downloaded:"
  head -c 300 "$ZIP_PATH"
  exit 1
fi

echo "Filtering to .bd domains ..."
# Tranco's CSV ships with CRLF line endings. A plain '\.bd$' anchor never
# matches because each line actually ends in "...bd\r" -- the trailing \r
# sits between the 'd' and the end-of-line anchor. Strip \r before filtering
# (confirmed against a live 0-result run on 2026-09-13 where 683 .bd domains
# were actually present in the raw file -- do not remove this tr without
# re-testing against a fresh CRLF download).
tr -d '\r' < "$CSV_PATH" | grep -E '\.bd$' > "${INTERIM_DIR}/tranco_bd_${DATE_TAG}.txt" || true

count=$(wc -l < "${INTERIM_DIR}/tranco_bd_${DATE_TAG}.txt" 2>/dev/null || echo 0)
echo "Found ${count} .bd domains in Tranco's top 1M."
echo ""
echo "Log this run in logs/collection_log.md:"
echo "  Date: ${DATE_TAG} | Script: fetch_tranco.sh | .bd domains found: ${count}"
