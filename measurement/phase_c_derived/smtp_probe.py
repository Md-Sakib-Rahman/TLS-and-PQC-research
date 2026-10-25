#!/usr/bin/env python3
"""
SMTP/STARTTLS probing engine for Phase C step 4.

WHAT IS SENT, AND WHAT NEVER IS
  Connect to port 25 -> read the banner -> EHLO <our hostname> -> if STARTTLS is offered, send
  STARTTLS and negotiate TLS -> QUIT. No MAIL FROM, no RCPT TO, no DATA: no email is ever composed,
  addressed, or sent. This mirrors b1's passive handshake-only design.
  The EHLO hostname identifies this study (configured, never a bare IP) -- the same reasoning as
  b2's required User-Agent: a mail admin who notices the connection can see what it is and reach us.

WHY THIS NO LONGER USES THE SYSTEM `ssl` MODULE (patched 2026-10-15, Phase D / E2a gap)
  This step originally asked only "is STARTTLS offered, and does a plain TLS handshake succeed
  afterwards" -- it didn't need PQ group visibility, so it used the system `ssl` module (the same
  way http_probe.py does) and stayed independent of tls_probe.py's special bundled-OpenSSL stack.
  That stopped being true once Phase D needed an HTTPS-vs-SMTP PQ-adoption comparison (the UK
  paper's core design, PLAN.md Section 3): the system OpenSSL on this machine cannot negotiate
  ML-KEM groups at all (same limitation tls_probe.py's own docstring documents), so the TLS-upgrade
  step after STARTTLS now uses the same pyOpenSSL + cryptography's bundled OpenSSL mechanism
  tls_probe.py uses for HTTPS, specifically to offer PQ groups in the ClientHello and read back
  which group the server actually chose (`group`, alongside the existing tls_version/cipher).
  The small amount of shared machinery (LIB/FFI binding, DEFAULT_GROUPS, is_pq_group) is duplicated
  here rather than imported from tls_probe.py, to keep this step resilient to either phase's
  package being restructured independently -- tls_probe.py remains the canonical source if the two
  ever need to be reconciled.
  Only ONE probe is run here (the PQ-offering default context), unlike tls_probe.py's multi-probe
  sequence (default/classical/legacy/pqc_only) -- so this records the raw `group` only. It
  deliberately does NOT attempt tls_probe.py's 5-state pq_class (pq_default/pq_capable_not_default/
  not_capable/no_tls13/unknown): distinguishing "not_capable" from "pq_capable_not_default" requires
  the secondary pqc_only probe tls_probe.py runs, which this step does not run, so claiming that
  distinction here would overstate what was actually tested. Classify PQ adoption downstream from
  `group` (is_pq_group(group)) and `tls_version`, the same way Phase D's analysis scripts already do
  for the HTTPS side.

SMTP REPLY FRAMING (RFC 5321 section 4.2)
  Each reply is one or more lines "CODE-text\\r\\n" (continuation) ending in exactly one
  "CODE text\\r\\n" (the space, not a dash, marks the last line) or "CODE\\r\\n" with nothing after
  the code. A reply is complete only once that final line has arrived; multiline EHLO replies
  (one capability per line) are the normal case, not an error.

STATUSES (per domain)
  ok              banner + EHLO + (if offered) STARTTLS all completed; starttls_offered says which
  no_starttls     EHLO completed, STARTTLS was not in the capability list -- a clear, real answer
  starttls_rejected STARTTLS was offered but the server's reply to it was not 2xx
  tls_failed      the server said 220 to STARTTLS but the TLS handshake itself failed
  smtp_error      a 4xx/5xx reply to the banner or EHLO (e.g. the server refused our hostname)
  timeout / connect_refused / connect_failed / closed / error  -- same meaning as elsewhere in this
                  project; never counted as "no STARTTLS" (Standing Rule 9)

  2026-10-15 NOTE on "timeout": "connect_timeout" is the ONLY status for a timeout during the TCP
  connect itself. A bare "timeout" status therefore always happens AFTER the connect already
  succeeded (waiting for a banner/EHLO/STARTTLS reply, or inside the TLS handshake), and now carries
  a "stage" field (one of "banner", "ehlo", "starttls", "tls_handshake") saying how far the exchange
  got before it stalled -- callers that need to tell "nothing was ever heard back" apart from "the
  host was clearly reachable and responsive but then stalled" (e.g. c4_smtp_scan.py's mid-run
  connect-level-failure safety net) should branch on this field rather than treating every "timeout"
  alike.

LIMITATIONS
  - Many mail servers also check the CONNECTING IP's reverse-DNS (PTR) record against the EHLO name.
    That record belongs to the scanning machine's ISP, not to anything this script controls, and a
    typical residential/office connection has no meaningful PTR set. A mismatch can cause
    smtp_error (REFUSED) or, rarely, a connection drop that looks like `closed` -- this is a known,
    stated limitation, not a bug in the probe.
  - Certificates are NOT validated here (verify_mode=CERT_NONE): mail server certificates are
    frequently self-signed or use a certificate meant for a different name (the MX hostname, not the
    domain), which is normal for SMTP and not itself a finding this step makes. Recording and
    scoring mail certificates the way b1 does for HTTPS was considered and left out of scope: it
    would double the work for a question the base papers do not ask either.
  - Only the lowest-preference MX host per domain is probed (the standard "primary" server per
    RFC 5321 section 5.1); secondary MX hosts are not probed.
"""

import re
import select
import socket
import time

from cryptography.hazmat.bindings.openssl.binding import Binding
from OpenSSL import SSL

DEFAULT_PORT = 25
REPLY_LINE = re.compile(rb"^(\d{3})([ -])(.*)\r\n", re.M)

# -- duplicated from tls_probe.py deliberately; see module docstring "WHY THIS NO LONGER USES..." --
_B = Binding()
LIB, FFI = _B.lib, _B.ffi
DEFAULT_GROUPS = "*X25519MLKEM768:*X25519:secp256r1:secp384r1"


def is_pq_group(name):
    return bool(name) and ("MLKEM" in name.upper() or "KYBER" in name.upper())


def _set_groups(ctx, groups):
    return LIB.SSL_CTX_set1_curves_list(ctx._context, groups.encode()) == 1
# -- end duplicated block --


def build_context(groups=DEFAULT_GROUPS):
    """A pyOpenSSL context that offers PQ groups, built the same way tls_probe.py's 'default'
    context is -- see the module docstring for why this replaced the system `ssl` module."""
    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)   # mail certs are out of scope here (unchanged)
    ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
    if not _set_groups(ctx, groups):
        raise RuntimeError(f"library rejected group list: {groups}")
    try:
        ctx.set_cipher_list(b"ALL:@SECLEVEL=0")
    except SSL.Error:
        pass
    return ctx


def _recv_reply(sock, timeout, max_bytes=16384):
    """
    Reads one complete SMTP reply (one or more lines; the last line's 4th byte is a space, not '-').
    Returns (code:int|None, lines:list[str], raw:bytes). code is None if the data never parsed as a
    reply at all (e.g. the peer sent plain HTTP, or nothing).
    """
    buf, deadline = b"", time.monotonic() + timeout
    while True:
        matches = list(REPLY_LINE.finditer(buf))
        if matches and matches[-1].group(2) == b" ":
            codes = {m.group(1) for m in matches}
            if len(codes) == 1:                                   # every line must share one reply code
                code = int(matches[0].group(1))
                lines = [m.group(3).decode("latin-1", "replace") for m in matches]
                return code, lines, buf
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(buf) >= max_bytes:
            return None, [], buf
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            return None, [], buf
        buf += chunk


def _send(sock, line):
    sock.sendall(line.encode("ascii", "ignore") + b"\r\n")


def probe_smtp(host, ip, ehlo_name, port=DEFAULT_PORT, timeout=10.0, ctx=None):
    """
    One connection: banner -> EHLO -> STARTTLS (if offered) -> TLS handshake -> QUIT. Never raises.
    `host` is the MX hostname used for logging only; `ehlo_name` is what we announce ourselves as.
    """
    t0 = time.monotonic()
    out = {"mx_host": host, "ip": ip, "ehlo_name": ehlo_name}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return {**out, "status": "connect_refused"}
    except (socket.timeout, TimeoutError):
        return {**out, "status": "connect_timeout"}
    except OSError as e:
        return {**out, "status": "connect_failed", "error": type(e).__name__}

    # Updated right before each command; used only if a plain socket timeout escapes to the bottom
    # `except` below, so that catch-all can report how far the exchange got (see module docstring,
    # the 2026-10-15 note on "timeout"). The explicit per-stage early returns elsewhere already carry
    # their own "stage", unaffected by this.
    stage = "banner"
    try:
        sock.settimeout(timeout)
        code, lines, _ = _recv_reply(sock, timeout)
        if code is None:
            return {**out, "status": "closed" if lines == [] else "error", "stage": "banner"}
        out["banner"] = lines[0][:200]
        if code >= 400:
            return {**out, "status": "smtp_error", "stage": "banner", "code": code, "detail": lines[0][:200]}

        stage = "ehlo"
        _send(sock, f"EHLO {ehlo_name}")
        code, lines, _ = _recv_reply(sock, timeout)
        if code is None:
            return {**out, "status": "closed", "stage": "ehlo"}
        if code >= 400:
            return {**out, "status": "smtp_error", "stage": "ehlo", "code": code, "detail": lines[0][:200]}
        out["capabilities"] = [ln.strip() for ln in lines]
        offered = any(ln.strip().upper().startswith("STARTTLS") for ln in lines)
        out["starttls_offered"] = offered
        if not offered:
            return {**out, "status": "no_starttls", "ms": round((time.monotonic() - t0) * 1000)}

        stage = "starttls"
        _send(sock, "STARTTLS")
        code, lines, _ = _recv_reply(sock, timeout)
        if code is None:
            return {**out, "status": "closed", "stage": "starttls"}
        if not (200 <= code < 300):
            return {**out, "status": "starttls_rejected", "code": code, "detail": lines[0][:200]}

        stage = "tls_handshake"
        tls_ctx = ctx or build_context()
        conn = None
        try:
            sock.setblocking(False)                 # switch to non-blocking only now -- plaintext
            conn = SSL.Connection(tls_ctx, sock)     # steps above already completed in blocking mode
            conn.set_tlsext_host_name(host.encode("idna"))
            conn.set_connect_state()
            deadline = time.monotonic() + timeout
            while True:
                try:
                    conn.do_handshake()
                    break
                except SSL.WantReadError:
                    r, _, _ = select.select([sock], [], [], max(0.0, deadline - time.monotonic()))
                except SSL.WantWriteError:
                    _, r, _ = select.select([], [sock], [], max(0.0, deadline - time.monotonic()))
                if not r and time.monotonic() >= deadline:
                    return {**out, "status": "timeout", "stage": "tls_handshake"}
        except SSL.Error as e:
            return {**out, "status": "tls_failed", "detail": str(e)[:200]}
        except OSError as e:
            return {**out, "status": "tls_failed", "detail": f"{type(e).__name__}: {e}"[:200]}

        p = LIB.SSL_get0_group_name(conn._ssl)
        out["tls_version"] = conn.get_protocol_version_name()
        out["cipher"] = conn.get_cipher_name()
        out["group"] = FFI.string(p).decode() if p != FFI.NULL else None   # None is a real answer
        try:                                                               # (classical/pre-TLS1.3/
            conn.send(b"QUIT\r\n")                                        #  unknown), not missing data
        except (SSL.WantWriteError, SSL.WantReadError, SSL.Error):
            pass
        try:
            select.select([sock], [], [], min(timeout, 5.0))
            conn.recv(200)                                    # best-effort; result doesn't matter
        except Exception:
            pass
        finally:
            try:
                conn.shutdown()
            except Exception:
                pass
            try:
                sock.setblocking(True)                        # outer `finally: sock.close()` expects this
            except Exception:
                pass
        return {**out, "status": "ok", "ms": round((time.monotonic() - t0) * 1000)}
    except (socket.timeout, TimeoutError):
        return {**out, "status": "timeout", "stage": stage}
    except (ConnectionResetError, BrokenPipeError):
        return {**out, "status": "closed", "stage": stage}
    except OSError as e:
        return {**out, "status": "error", "detail": f"{type(e).__name__}: {e}"[:200], "stage": stage}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def resolve_mx_ip(mx_host, timeout=5.0):
    """A plain A-record lookup for one MX hostname (stdlib only, no dnspython dependency here)."""
    try:
        return socket.getaddrinfo(mx_host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)[0][4][0]
    except (socket.gaierror, IndexError):
        return None


def control_check(host="smtp.gmail.com", port=DEFAULT_PORT, ehlo_name="probe-selftest.invalid", timeout=10.0):
    """Positive control: a known STARTTLS-supporting public mail server must show it. Used before a
    real run to catch a broken probe or a network that blocks/intercepts port 25 outbound."""
    ip = resolve_mx_ip(host, timeout)
    if not ip:
        return {"status": "resolve_failed"}, False
    r = probe_smtp(host, ip, ehlo_name, port, timeout)
    return r, r.get("status") == "ok" and r.get("starttls_offered") is True


# #!/usr/bin/env python3
# """
# SMTP/STARTTLS probing engine for Phase C step 4.

# WHAT IS SENT, AND WHAT NEVER IS
#   Connect to port 25 -> read the banner -> EHLO <our hostname> -> if STARTTLS is offered, send
#   STARTTLS and negotiate TLS -> QUIT. No MAIL FROM, no RCPT TO, no DATA: no email is ever composed,
#   addressed, or sent. This mirrors b1's passive handshake-only design.
#   The EHLO hostname identifies this study (configured, never a bare IP) -- the same reasoning as
#   b2's required User-Agent: a mail admin who notices the connection can see what it is and reach us.

# WHY THIS NO LONGER USES THE SYSTEM `ssl` MODULE (patched 2026-10-15, Phase D / E2a gap)
#   This step originally asked only "is STARTTLS offered, and does a plain TLS handshake succeed
#   afterwards" -- it didn't need PQ group visibility, so it used the system `ssl` module (the same
#   way http_probe.py does) and stayed independent of tls_probe.py's special bundled-OpenSSL stack.
#   That stopped being true once Phase D needed an HTTPS-vs-SMTP PQ-adoption comparison (the UK
#   paper's core design, PLAN.md Section 3): the system OpenSSL on this machine cannot negotiate
#   ML-KEM groups at all (same limitation tls_probe.py's own docstring documents), so the TLS-upgrade
#   step after STARTTLS now uses the same pyOpenSSL + cryptography's bundled OpenSSL mechanism
#   tls_probe.py uses for HTTPS, specifically to offer PQ groups in the ClientHello and read back
#   which group the server actually chose (`group`, alongside the existing tls_version/cipher).
#   The small amount of shared machinery (LIB/FFI binding, DEFAULT_GROUPS, is_pq_group) is duplicated
#   here rather than imported from tls_probe.py, to keep this step resilient to either phase's
#   package being restructured independently -- tls_probe.py remains the canonical source if the two
#   ever need to be reconciled.
#   Only ONE probe is run here (the PQ-offering default context), unlike tls_probe.py's multi-probe
#   sequence (default/classical/legacy/pqc_only) -- so this records the raw `group` only. It
#   deliberately does NOT attempt tls_probe.py's 5-state pq_class (pq_default/pq_capable_not_default/
#   not_capable/no_tls13/unknown): distinguishing "not_capable" from "pq_capable_not_default" requires
#   the secondary pqc_only probe tls_probe.py runs, which this step does not run, so claiming that
#   distinction here would overstate what was actually tested. Classify PQ adoption downstream from
#   `group` (is_pq_group(group)) and `tls_version`, the same way Phase D's analysis scripts already do
#   for the HTTPS side.

# SMTP REPLY FRAMING (RFC 5321 section 4.2)
#   Each reply is one or more lines "CODE-text\\r\\n" (continuation) ending in exactly one
#   "CODE text\\r\\n" (the space, not a dash, marks the last line) or "CODE\\r\\n" with nothing after
#   the code. A reply is complete only once that final line has arrived; multiline EHLO replies
#   (one capability per line) are the normal case, not an error.

# STATUSES (per domain)
#   ok              banner + EHLO + (if offered) STARTTLS all completed; starttls_offered says which
#   no_starttls     EHLO completed, STARTTLS was not in the capability list -- a clear, real answer
#   starttls_rejected STARTTLS was offered but the server's reply to it was not 2xx
#   tls_failed      the server said 220 to STARTTLS but the TLS handshake itself failed
#   smtp_error      a 4xx/5xx reply to the banner or EHLO (e.g. the server refused our hostname)
#   timeout / connect_refused / connect_failed / closed / error  -- same meaning as elsewhere in this
#                   project; never counted as "no STARTTLS" (Standing Rule 9)

# LIMITATIONS
#   - Many mail servers also check the CONNECTING IP's reverse-DNS (PTR) record against the EHLO name.
#     That record belongs to the scanning machine's ISP, not to anything this script controls, and a
#     typical residential/office connection has no meaningful PTR set. A mismatch can cause
#     smtp_error (REFUSED) or, rarely, a connection drop that looks like `closed` -- this is a known,
#     stated limitation, not a bug in the probe.
#   - Certificates are NOT validated here (verify_mode=CERT_NONE): mail server certificates are
#     frequently self-signed or use a certificate meant for a different name (the MX hostname, not the
#     domain), which is normal for SMTP and not itself a finding this step makes. Recording and
#     scoring mail certificates the way b1 does for HTTPS was considered and left out of scope: it
#     would double the work for a question the base papers do not ask either.
#   - Only the lowest-preference MX host per domain is probed (the standard "primary" server per
#     RFC 5321 section 5.1); secondary MX hosts are not probed.
# """

# import re
# import select
# import socket
# import time

# from cryptography.hazmat.bindings.openssl.binding import Binding
# from OpenSSL import SSL

# DEFAULT_PORT = 25
# REPLY_LINE = re.compile(rb"^(\d{3})([ -])(.*)\r\n", re.M)

# # -- duplicated from tls_probe.py deliberately; see module docstring "WHY THIS NO LONGER USES..." --
# _B = Binding()
# LIB, FFI = _B.lib, _B.ffi
# DEFAULT_GROUPS = "*X25519MLKEM768:*X25519:secp256r1:secp384r1"


# def is_pq_group(name):
#     return bool(name) and ("MLKEM" in name.upper() or "KYBER" in name.upper())


# def _set_groups(ctx, groups):
#     return LIB.SSL_CTX_set1_curves_list(ctx._context, groups.encode()) == 1
# # -- end duplicated block --


# def build_context(groups=DEFAULT_GROUPS):
#     """A pyOpenSSL context that offers PQ groups, built the same way tls_probe.py's 'default'
#     context is -- see the module docstring for why this replaced the system `ssl` module."""
#     ctx = SSL.Context(SSL.TLS_METHOD)
#     ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)   # mail certs are out of scope here (unchanged)
#     ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
#     if not _set_groups(ctx, groups):
#         raise RuntimeError(f"library rejected group list: {groups}")
#     try:
#         ctx.set_cipher_list(b"ALL:@SECLEVEL=0")
#     except SSL.Error:
#         pass
#     return ctx


# def _recv_reply(sock, timeout, max_bytes=16384):
#     """
#     Reads one complete SMTP reply (one or more lines; the last line's 4th byte is a space, not '-').
#     Returns (code:int|None, lines:list[str], raw:bytes). code is None if the data never parsed as a
#     reply at all (e.g. the peer sent plain HTTP, or nothing).
#     """
#     buf, deadline = b"", time.monotonic() + timeout
#     while True:
#         matches = list(REPLY_LINE.finditer(buf))
#         if matches and matches[-1].group(2) == b" ":
#             codes = {m.group(1) for m in matches}
#             if len(codes) == 1:                                   # every line must share one reply code
#                 code = int(matches[0].group(1))
#                 lines = [m.group(3).decode("latin-1", "replace") for m in matches]
#                 return code, lines, buf
#         remaining = deadline - time.monotonic()
#         if remaining <= 0 or len(buf) >= max_bytes:
#             return None, [], buf
#         sock.settimeout(remaining)
#         chunk = sock.recv(4096)
#         if not chunk:
#             return None, [], buf
#         buf += chunk


# def _send(sock, line):
#     sock.sendall(line.encode("ascii", "ignore") + b"\r\n")


# def probe_smtp(host, ip, ehlo_name, port=DEFAULT_PORT, timeout=10.0, ctx=None):
#     """
#     One connection: banner -> EHLO -> STARTTLS (if offered) -> TLS handshake -> QUIT. Never raises.
#     `host` is the MX hostname used for logging only; `ehlo_name` is what we announce ourselves as.
#     """
#     t0 = time.monotonic()
#     out = {"mx_host": host, "ip": ip, "ehlo_name": ehlo_name}
#     try:
#         sock = socket.create_connection((ip, port), timeout=timeout)
#     except ConnectionRefusedError:
#         return {**out, "status": "connect_refused"}
#     except (socket.timeout, TimeoutError):
#         return {**out, "status": "connect_timeout"}
#     except OSError as e:
#         return {**out, "status": "connect_failed", "error": type(e).__name__}

#     try:
#         sock.settimeout(timeout)
#         code, lines, _ = _recv_reply(sock, timeout)
#         if code is None:
#             return {**out, "status": "closed" if lines == [] else "error", "stage": "banner"}
#         out["banner"] = lines[0][:200]
#         if code >= 400:
#             return {**out, "status": "smtp_error", "stage": "banner", "code": code, "detail": lines[0][:200]}

#         _send(sock, f"EHLO {ehlo_name}")
#         code, lines, _ = _recv_reply(sock, timeout)
#         if code is None:
#             return {**out, "status": "closed", "stage": "ehlo"}
#         if code >= 400:
#             return {**out, "status": "smtp_error", "stage": "ehlo", "code": code, "detail": lines[0][:200]}
#         out["capabilities"] = [ln.strip() for ln in lines]
#         offered = any(ln.strip().upper().startswith("STARTTLS") for ln in lines)
#         out["starttls_offered"] = offered
#         if not offered:
#             return {**out, "status": "no_starttls", "ms": round((time.monotonic() - t0) * 1000)}

#         _send(sock, "STARTTLS")
#         code, lines, _ = _recv_reply(sock, timeout)
#         if code is None:
#             return {**out, "status": "closed", "stage": "starttls"}
#         if not (200 <= code < 300):
#             return {**out, "status": "starttls_rejected", "code": code, "detail": lines[0][:200]}

#         tls_ctx = ctx or build_context()
#         conn = None
#         try:
#             sock.setblocking(False)                 # switch to non-blocking only now -- plaintext
#             conn = SSL.Connection(tls_ctx, sock)     # steps above already completed in blocking mode
#             conn.set_tlsext_host_name(host.encode("idna"))
#             conn.set_connect_state()
#             deadline = time.monotonic() + timeout
#             while True:
#                 try:
#                     conn.do_handshake()
#                     break
#                 except SSL.WantReadError:
#                     r, _, _ = select.select([sock], [], [], max(0.0, deadline - time.monotonic()))
#                 except SSL.WantWriteError:
#                     _, r, _ = select.select([], [sock], [], max(0.0, deadline - time.monotonic()))
#                 if not r and time.monotonic() >= deadline:
#                     return {**out, "status": "timeout", "stage": "tls_handshake"}
#         except SSL.Error as e:
#             return {**out, "status": "tls_failed", "detail": str(e)[:200]}
#         except OSError as e:
#             return {**out, "status": "tls_failed", "detail": f"{type(e).__name__}: {e}"[:200]}

#         p = LIB.SSL_get0_group_name(conn._ssl)
#         out["tls_version"] = conn.get_protocol_version_name()
#         out["cipher"] = conn.get_cipher_name()
#         out["group"] = FFI.string(p).decode() if p != FFI.NULL else None   # None is a real answer
#         try:                                                               # (classical/pre-TLS1.3/
#             conn.send(b"QUIT\r\n")                                        #  unknown), not missing data
#         except (SSL.WantWriteError, SSL.WantReadError, SSL.Error):
#             pass
#         try:
#             select.select([sock], [], [], min(timeout, 5.0))
#             conn.recv(200)                                    # best-effort; result doesn't matter
#         except Exception:
#             pass
#         finally:
#             try:
#                 conn.shutdown()
#             except Exception:
#                 pass
#             try:
#                 sock.setblocking(True)                        # outer `finally: sock.close()` expects this
#             except Exception:
#                 pass
#         return {**out, "status": "ok", "ms": round((time.monotonic() - t0) * 1000)}
#     except (socket.timeout, TimeoutError):
#         return {**out, "status": "timeout"}
#     except (ConnectionResetError, BrokenPipeError):
#         return {**out, "status": "closed"}
#     except OSError as e:
#         return {**out, "status": "error", "detail": f"{type(e).__name__}: {e}"[:200]}
#     finally:
#         try:
#             sock.close()
#         except Exception:
#             pass


# def resolve_mx_ip(mx_host, timeout=5.0):
#     """A plain A-record lookup for one MX hostname (stdlib only, no dnspython dependency here)."""
#     try:
#         return socket.getaddrinfo(mx_host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)[0][4][0]
#     except (socket.gaierror, IndexError):
#         return None


# def control_check(host="smtp.gmail.com", port=DEFAULT_PORT, ehlo_name="probe-selftest.invalid", timeout=10.0):
#     """Positive control: a known STARTTLS-supporting public mail server must show it. Used before a
#     real run to catch a broken probe or a network that blocks/intercepts port 25 outbound."""
#     ip = resolve_mx_ip(host, timeout)
#     if not ip:
#         return {"status": "resolve_failed"}, False
#     r = probe_smtp(host, ip, ehlo_name, port, timeout)
#     return r, r.get("status") == "ok" and r.get("starttls_offered") is True