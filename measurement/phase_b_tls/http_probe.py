#!/usr/bin/env python3
"""
HTTP-over-TLS header probe for Phase B, step 2 (b2): HSTS detection and passive WAF vendor
signature matching, from the plain HTTP response headers an ordinary browser's first GET / would
see. One request per domain; no forms submitted, no crawling, no authentication attempted.

WHY A SEPARATE, SIMPLER TLS PATH THAN b1/tls_probe.py
  b1's TLS stack exists specifically to see which key-exchange group gets negotiated, which
  needs the special pyOpenSSL/cryptography build documented there. That is irrelevant here --
  b2 only needs the HTTP response headers, so it uses the plain system `ssl` module and is
  independent of that version pinning. b2's context is also tuned the OPPOSITE way from a
  "browser" probe: minimum TLS version as low as the library allows, and certificate
  verification off, so a domain b1 found on TLS 1.0 (legacy_only) or with an untrusted
  certificate still gets its headers collected. HTTP behaviour is measured independently of
  TLS/certificate posture, the same way each earlier phase measures one thing without assuming
  a domain "passed" a previous one.

REQUEST
  A single "GET / HTTP/1.1" with Host, Accept, Connection: close, and the configured
  identifying User-Agent (see config.yaml -- MUST be filled in with a contact URL/email before
  the real run: this is the first script in the pipeline that makes a request a server operator
  could plausibly notice or log, and identifying research scans is standard measurement-ethics
  practice, e.g. Durumeric et al.). ALPN is restricted to http/1.1 only, so a server that would
  otherwise negotiate HTTP/2 sends a plain-text response this probe can parse; that HTTP/2 vs
  HTTP/1.1 preference is itself not measured here. Redirects (3xx) are recorded but NOT
  followed -- this keeps the probe to one request per domain and matches the project's
  passive-only scope; a redirect's Location header is still captured as data.

HSTS
  Parsed from the Strict-Transport-Security response header if present: max-age,
  includeSubDomains, preload. `present: false` means the header was absent in THIS response;
  a domain that only sets HSTS after a redirect, or only on some paths, will read as absent.

WAF DETECTION (passive, header-based only)
  Response headers (and Set-Cookie) are checked against a signature table of well-known
  CDN/WAF vendors (Cloudflare, Akamai, Imperva/Incapsula, Sucuri, AWS CloudFront, Fastly,
  F5 BIG-IP, Azure Front Door, Google Front End, Barracuda). This is a heuristic, not proof:
  absence of a match means "no known signature seen", not "no WAF present" -- an operator can
  strip or rename identifying headers. It also cannot distinguish a WAF from a plain CDN that
  merely happens to sit in front of the origin; both are recorded as a "vendor" match, and the
  distinction, if it matters, has to be made by hand afterward. The signature list is not
  exhaustive.

LIMITATIONS
  - Root path "/" only; a WAF or HSTS policy that applies only to specific paths is not seen.
  - SSLv3 cannot be tested even at the low end (same caveat as tls_probe.py): the system
    OpenSSL build here has no SSLv3 support, so the effective floor is whatever it allows,
    logged in `min_tls_version_available`.
  - No cookies are sent (no session), and no JavaScript runs, so a WAF that only engages after
    a JS challenge or repeat visits is invisible to a single passive GET.
"""

import re
import socket
import ssl
import time

DEFAULT_UA = "bd-tls-pqc-study/1.0"
MAX_STATUS_LINE = 200

# (vendor, header name (lowercase), regex matched against that header's value, case-insensitive)
# Ordered but not exclusive -- a response can match several rows (e.g. a WAF fronted by a CDN).
WAF_SIGNATURES = [
    ("Cloudflare", "server", r"cloudflare"),
    ("Cloudflare", "cf-ray", r".+"),
    ("Cloudflare", "cf-cache-status", r".+"),
    ("Akamai", "server", r"akamaighost"),
    ("Akamai", "x-akamai-transformed", r".+"),
    ("Akamai", "akamai-x-cache-on", r".+"),
    ("Imperva/Incapsula", "x-iinfo", r".+"),
    ("Imperva/Incapsula", "x-cdn", r"incapsula"),
    ("Sucuri", "x-sucuri-id", r".+"),
    ("Sucuri", "server", r"sucuri"),
    ("AWS CloudFront", "x-amz-cf-id", r".+"),
    ("AWS CloudFront", "via", r"cloudfront"),
    ("Fastly", "x-served-by", r"cache-"),
    ("Fastly", "x-fastly-request-id", r".+"),
    ("F5 BIG-IP ASM", "server", r"big-?ip"),
    ("Azure Front Door/WAF", "x-azure-ref", r".+"),
    ("Google Front End", "server", r"\bgfe\b|google frontend"),
    ("Barracuda", "server", r"barracuda"),
]
_COOKIE_SIGNATURES = [("Imperva/Incapsula", r"incap_ses_|visid_incap_")]


def build_context(alpn=("http/1.1",)):
    """A context that maximizes how many servers respond (low TLS floor, no verification),
    the opposite tuning from tls_probe.py's browser-like probe -- see module docstring."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    min_requested = "TLSv1.2"                               # SSLContext's own floor if all attempts fail
    for version, label in ((ssl.TLSVersion.SSLv3, "SSLv3"), (ssl.TLSVersion.TLSv1, "TLSv1"),
                           (ssl.TLSVersion.TLSv1_1, "TLSv1.1")):
        try:
            ctx.minimum_version = version
            min_requested = label
            break
        except (ValueError, OSError):
            continue
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.set_alpn_protocols(list(alpn))
    # NOTE: this only records what the SSLContext ACCEPTED being set, not a guarantee that a
    # handshake at that version will actually succeed (e.g. a build with SSLv3's version enum
    # present but no working SSLv3 cipher stack will still fail any real SSLv3 handshake).
    ctx.min_tls_version_requested = min_requested
    return ctx


def _request_bytes(host, user_agent):
    return (f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n").encode("ascii", "ignore")


def parse_response(head_bytes):
    """head_bytes: everything up to (not including) the blank line that ends the headers."""
    try:
        text = head_bytes.decode("iso-8859-1")
    except Exception:
        return {"status": "parse_error"}
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return {"status": "empty_response"}
    m = re.match(r"HTTP/(\d\.\d)\s+(\d{3})(?:\s+(.*))?", lines[0])
    if not m:
        return {"status": "bad_status_line", "raw": lines[0][:MAX_STATUS_LINE]}
    headers, order = {}, []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        headers.setdefault(k, []).append(v)
        order.append((k, v))
    return {"status": "ok", "http_version": m.group(1), "status_code": int(m.group(2)),
            "reason": (m.group(3) or "")[:MAX_STATUS_LINE],
            "headers": {k: "; ".join(v) for k, v in headers.items()},
            "raw_header_lines": [f"{k}: {v}" for k, v in order]}


def fetch_headers(host, ip, port=443, timeout=10.0, user_agent=DEFAULT_UA, ctx=None,
                  max_bytes=65536):
    """Never raises. Returns a dict with 'status' plus, on 'ok', http_version/status_code/
    reason/headers/raw_header_lines. Other statuses: connect_refused | connect_timeout |
    connect_error | tls_error | timeout | empty_response | incomplete_response |
    headers_too_large | parse_error | bad_status_line | error.
    'ok' is returned ONLY when the header-terminating blank line (\\r\\n\\r\\n) was actually
    seen -- a response that got cut off (peer closed early, or exceeded max_bytes before the
    terminator) is never parsed as if it were complete; that would silently feed truncated,
    misleading header values into HSTS/WAF detection."""
    ctx = ctx or build_context()
    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return {"status": "connect_refused"}
    except (socket.timeout, TimeoutError):
        return {"status": "connect_timeout"}
    except OSError as e:
        return {"status": "connect_error", "error": type(e).__name__}
    sock = raw_sock
    try:
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(_request_bytes(host, user_agent))
        data, deadline, reason = b"", time.monotonic() + timeout, None
        while True:
            if b"\r\n\r\n" in data:
                reason = "complete"
                break
            if len(data) >= max_bytes:
                reason = "too_large"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"status": "timeout"}
            sock.settimeout(remaining)
            chunk = sock.recv(8192)
            if not chunk:
                reason = "closed"
                break
            data += chunk
        if reason == "complete":
            return parse_response(data.split(b"\r\n\r\n", 1)[0])
        if not data:
            return {"status": "empty_response"}
        if reason == "too_large":
            return {"status": "headers_too_large"}
        return {"status": "incomplete_response"}          # peer closed before the terminator
    except ssl.SSLError as e:
        return {"status": "tls_error", "error": str(e)[:200]}
    except (socket.timeout, TimeoutError):
        return {"status": "timeout"}
    except OSError as e:
        return {"status": "connect_error", "error": f"{type(e).__name__}: {e}"[:200]}
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"[:200]}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def parse_hsts(headers):
    v = headers.get("strict-transport-security")
    if not v:
        return {"present": False}
    m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
    return {"present": True, "raw": v[:300], "max_age": int(m.group(1)) if m else None,
            "include_subdomains": bool(re.search(r"includesubdomains", v, re.I)),
            "preload": bool(re.search(r"\bpreload\b", v, re.I))}


def detect_waf(headers):
    hits = []
    for vendor, hname, pattern in WAF_SIGNATURES:
        val = headers.get(hname)
        if val and re.search(pattern, val, re.I):
            hits.append({"vendor": vendor, "header": hname, "value": val[:200]})
    cookies = headers.get("set-cookie", "")
    for vendor, pattern in _COOKIE_SIGNATURES:
        if re.search(pattern, cookies, re.I):
            hits.append({"vendor": vendor, "header": "set-cookie", "value": "signature match"})
    return {"detected": bool(hits), "vendors": sorted({h["vendor"] for h in hits}), "evidence": hits}


def probe_domain(host, ip, port=443, timeout=10.0, user_agent=DEFAULT_UA, ctx=None, max_bytes=65536):
    resp = fetch_headers(host, ip, port, timeout, user_agent, ctx, max_bytes)
    if resp.get("status") != "ok":
        return {"domain": host, "ip": ip, **resp, "hsts": None, "waf": None}
    return {"domain": host, "ip": ip, **resp,
            "hsts": parse_hsts(resp["headers"]), "waf": detect_waf(resp["headers"])}


def control_check(hosts, ctx, port=443, timeout=10.0, resolve=None):
    """Positive control: a known Cloudflare-fronted host must return a response whose headers
    actually show the Cloudflare signature. Fails if headers are being stripped or rewritten
    somewhere on the network path (e.g. a proxy), which would silently blank the WAF/HSTS data
    for the whole scan."""
    resolve = resolve or (lambda h: socket.getaddrinfo(h, port, type=socket.SOCK_STREAM)[0][4][0])
    results, ok = {}, False
    for h in hosts:
        try:
            ip = resolve(h)
        except Exception as e:
            results[h] = {"status": "resolve_failed", "error": type(e).__name__}
            continue
        r = probe_domain(h, ip, port, timeout, DEFAULT_UA, ctx)
        results[h] = r
        ok = ok or (r.get("status") == "ok" and r.get("waf", {}).get("detected"))
    return results, ok