#!/usr/bin/env bash
# Builds a PRIVATE OpenSSL 1.1.1w with SSLv3 and weak ciphers (3DES, RC4) ENABLED.
# Used ONLY by the Phase C step 2b legacy probe (measurement/phase_c_derived/c2b_legacy_scan.py).
# Nothing is installed system-wide: everything goes into one folder that can be deleted safely.
#
# Why it is needed: the main scanner's OpenSSL (4.x, bundled in the `cryptography` wheel) has SSLv3,
# 3DES, DES, RC2 and RC4 compiled OUT, so it can never offer them to a server.
# OpenSSL 1.1.1 is end-of-life; that is acceptable here because it is only used as a test CLIENT.
#
# Usage:   bash tools/build_legacy_openssl.sh [install_dir]     (default: tools/legacy_openssl)
# Needs:   gcc, make, perl, curl, tar   (Ubuntu/Debian: sudo apt install build-essential perl curl)
set -euo pipefail

VERSION=1.1.1w
# SHA-256 of openssl-1.1.1w.tar.gz as downloaded on 2026-09-27; compare it with the value published
# on openssl.org/source/old/1.1.1/ before trusting this script for a publication.
SHA256=cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8
URLS=("https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/openssl-${VERSION}.tar.gz"
      "https://www.openssl.org/source/old/1.1.1/openssl-${VERSION}.tar.gz")

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${1:-$HERE/legacy_openssl}"

for tool in gcc make perl curl tar sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: '$tool' not found (Ubuntu/Debian: sudo apt install build-essential perl curl)"; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

ok=0
for url in "${URLS[@]}"; do
  echo "Downloading $url"
  if curl -fsSL -o src.tar.gz "$url"; then ok=1; break; fi
done
[ "$ok" = 1 ] || { echo "ERROR: download failed from every mirror"; exit 1; }

echo "$SHA256  src.tar.gz" | sha256sum -c - || { echo "ERROR: checksum mismatch -- refusing to build"; exit 1; }

tar xzf src.tar.gz
cd "openssl-${VERSION}"
echo "Configuring (SSLv3 + weak ciphers enabled, static, private prefix: $PREFIX)"
./config --prefix="$PREFIX" --openssldir="$PREFIX/ssl" \
         enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers no-shared >/dev/null
echo "Compiling (about a minute)..."
make -j"$(nproc)" >/dev/null 2>&1
make install_sw >/dev/null 2>&1

BIN="$PREFIX/bin/openssl"
"$BIN" version
"$BIN" s_client -help 2>&1 | grep -q -- "-ssl3" || { echo "ERROR: built binary has no -ssl3 option"; exit 1; }
"$BIN" ciphers -v '3DES:@SECLEVEL=0' 2>/dev/null | grep -q "DES-CBC3" || { echo "ERROR: built binary has no 3DES"; exit 1; }
echo "OK: $BIN (SSLv3 and 3DES available)"
