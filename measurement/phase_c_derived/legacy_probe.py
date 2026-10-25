#!/usr/bin/env python3
"""
Legacy-protocol probes for Phase C step 2b: SSLv3 acceptance (POODLE precondition) and 3DES
acceptance (Sweet32-class), using a PRIVATE OpenSSL 1.1.1w build with SSLv3 and weak ciphers
enabled (tools/build_legacy_openssl.sh).

WHY A SEPARATE OPENSSL
  The main scanner (tls_probe.py) runs on the OpenSSL 4.x bundled in the `cryptography` wheel, which
  has SSLv3, 3DES, DES, RC2 and RC4 compiled OUT. A client can only detect what it can OFFER (the
  server picks from the client's list), so that scanner could never see these. This module shells out
  to `openssl s_client` from the legacy build instead. OpenSSL 1.1.1 is end-of-life; that is fine for a
  test CLIENT, and the paper must state the version.

THE TWO PROBES
  SSLv3 probe (once per IP -- see below)
    A: offer SSLv3 with every cipher (ALL:@SECLEVEL=0).
       refused/closed/no response -> the server does not accept SSLv3 (or gave no answer).
       accepted with a CBC cipher -> POODLE-exposed (SSLv3 + CBC padding).
       accepted with RC4 (the only non-CBC SSLv3 cipher) -> SSLv3 is on, but that pick says nothing
       about CBC: a server may prefer RC4 while also enabling CBC.
    B: only when A was accepted with a non-CBC cipher: re-offer SSLv3 with CBC ciphers ONLY
       (ALL:!RC4:!NULL:!eNULL). Accepted -> POODLE-exposed; refused -> SSLv3 on but not POODLE-exposed.
       (Checked with real handshakes: an RC4-preferring server that also enabled AES-CBC looks harmless
       on probe A and is exposed by probe B.)
  3DES probe (once per DOMAIN, with SNI)
    Offer only 3DES suites (3DES:@SECLEVEL=0) on TLS 1.0-1.2 (-no_tls1_3). Accepted -> the server still
    supports 3DES when offered. Report it as "accepts 3DES when offered", NOT "Sweet32-vulnerable":
    modern clients no longer offer 3DES, so the practical risk is to old clients and to long sessions
    of 64-bit-block traffic.

WHY SSLv3 IS PER IP AND 3DES PER DOMAIN
  SSLv3 has no extensions, so it cannot carry the hostname (SNI). Verified: the SSLv3 ClientHello is
  the same size (0x65 bytes) with and without -servername, while the TLS 1.0-1.2 hello grows from 0x95
  to 0xca bytes when the hostname is added. A server therefore cannot tell which domain an SSLv3
  client wants, so probing SSLv3 once per domain would send byte-identical hellos: one probe per IP is
  exact, with no assumption, and avoids hitting big shared hosts hundreds of times.

PARSING PITFALLS (learned from real output; the tests use captured s_client text)
  - The line "New, SSLv3, Cipher is DES-CBC3-SHA" shows the protocol the CIPHER was introduced in, not the
    negotiated protocol (the same connection reported "Protocol : TLSv1.2" in the session block).
  - A FAILED handshake still prints "Protocol : SSLv3" (what we offered) together with "Cipher : 0000"
    and "New, (NONE), Cipher is (NONE)". Success is decided ONLY by a real cipher name in the session
    block; "0000" / "(NONE)" mean failure.
  - Application data is never sent (stdin is empty); only the handshake and a close_notify happen.

STATUSES (per connection)
  accepted        handshake completed with a real cipher
  refused         a TLS alert or protocol error (e.g. handshake failure, protocol version, wrong version)
  closed          TCP connected, then the server closed without a TLS answer (EOF / reset)
  timeout         no answer within the timeout
  connect_failed  TCP connection could not be made (refused, unreachable, ...)
  error           the probe itself failed (bad input, binary problem)
  accepts_* is True for accepted; False for refused/closed; None for timeout/connect_failed/error
  (inconclusive is never counted as "no", as everywhere in this project).

NOT COVERED
  Heartbleed (needs a malformed heartbeat that extracts server memory: active exploitation, out of
  scope by project rule) and "POODLE over TLS" (needs records with corrupted padding). Both are reported
  as not tested.
"""

import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager

from measurement.phase_c_derived.c2_legacy_cipher_inference import is_cbc_mode

SSLV3_ALL = "ALL:@SECLEVEL=0"
SSLV3_CBC_ONLY = "ALL:!RC4:!NULL:!eNULL:@SECLEVEL=0"
DES3 = "3DES:@SECLEVEL=0"

HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_CIPHER = re.compile(r"^\s*Cipher\s*:\s*(\S+)", re.M)
_PROTO = re.compile(r"^\s*Protocol\s*:\s*(\S+)", re.M)
_CONNECT_ERRNO = re.compile(r"connect:errno=(\d+)")
_IO_ERRNO = re.compile(r"(?:read|write):errno=(\d+)")
_ALERT_NUM = re.compile(r"SSL alert number (\d+)")
_ERROR_LINE = re.compile(r"SSL routines:[A-Za-z0-9_]+:([^:]+):")
FAILED_CIPHERS = {"0000", "(NONE)", "NONE"}
REFUSAL_WORDS = ("alert", "wrong version number", "unknown protocol", "unsupported protocol",
                 "no protocols available", "version too low", "no shared cipher", "no ciphers available")


# ---------------------------------------------------------------- parsing

def parse_s_client(text):
    """Classify one `openssl s_client` run from its combined stdout+stderr. Pure function."""
    if "CONNECTED(" not in text:
        m = _CONNECT_ERRNO.search(text)
        return {"status": "connect_failed", "detail": f"errno={m.group(1)}" if m else "no connection"}
    cm, pm = _CIPHER.search(text), _PROTO.search(text)
    cipher = cm.group(1) if cm else None
    if cipher and cipher not in FAILED_CIPHERS and "New, (NONE)" not in text:
        return {"status": "accepted", "protocol": pm.group(1) if pm else None, "cipher": cipher}
    low = text.lower()
    if any(w in low for w in REFUSAL_WORDS):
        n, e = _ALERT_NUM.search(text), _ERROR_LINE.search(text)
        detail = (e.group(1).strip() if e else "protocol error") + (f" (alert {n.group(1)})" if n else "")
        return {"status": "refused", "detail": detail}
    m = _IO_ERRNO.search(text)
    return {"status": "closed", "detail": f"errno={m.group(1)}" if m and m.group(1) != "0"
            else "server closed without a TLS answer"}


def tri_state(status):
    """accepted -> True; refused/closed -> False; anything inconclusive -> None."""
    if status == "accepted":
        return True
    if status in ("refused", "closed"):
        return False
    return None


def target_for(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def run_s_client(openssl, target, args, timeout):
    cmd = [openssl, "s_client", "-connect", target, *args]
    try:
        p = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except (OSError, ValueError) as e:
        return {"status": "error", "detail": f"{type(e).__name__}: {e}"[:200]}
    return parse_s_client((p.stdout + p.stderr).decode("latin-1", "replace"))


# ---------------------------------------------------------------- probes

def _check_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def probe_sslv3(openssl, ip, port=443, timeout=10.0, pace=None):
    """SSLv3 acceptance + POODLE exposure for one IP. `pace()` is called before every connection."""
    if not _check_ip(ip):
        return {"accepts_sslv3": None, "poodle_exposed": None, "offer_all": {"status": "error", "detail": "bad ip"},
                "offer_cbc": None}
    if pace:
        pace()
    a = run_s_client(openssl, target_for(ip, port), ["-ssl3", "-cipher", SSLV3_ALL], timeout)
    out = {"offer_all": a, "offer_cbc": None, "accepts_sslv3": tri_state(a["status"])}
    if a["status"] == "accepted":
        if is_cbc_mode(a.get("cipher")):
            out["poodle_exposed"] = True
        else:                                     # RC4 pick: ask again offering CBC ciphers only
            if pace:
                pace()
            b = run_s_client(openssl, target_for(ip, port), ["-ssl3", "-cipher", SSLV3_CBC_ONLY], timeout)
            out["offer_cbc"] = b
            out["poodle_exposed"] = tri_state(b["status"])
    else:
        out["poodle_exposed"] = False if out["accepts_sslv3"] is False else None
    return out


def probe_3des(openssl, host, ip, port=443, timeout=10.0, pace=None):
    """3DES acceptance for one domain (SNI = host) on TLS 1.0-1.2."""
    if not HOST_RE.match(host or "") or not _check_ip(ip):
        return {"status": "error", "detail": "invalid host or ip", "accepts_3des": None}
    if pace:
        pace()
    r = run_s_client(openssl, target_for(ip, port), ["-no_tls1_3", "-cipher", DES3, "-servername", host], timeout)
    r["accepts_3des"] = tri_state(r["status"])
    if r["status"] == "accepted" and not re.search(r"3DES|DES-CBC3", r.get("cipher") or ""):
        r["accepts_3des"] = None                  # cannot happen by construction; never guess if it does
        r["detail"] = "unexpected non-3DES cipher"
    return r


def tcp_reachable(ip, port, timeout=5.0):
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return True
    except OSError:
        return False


# ---------------------------------------------------------------- binary checks and local controls

def check_capabilities(openssl):
    """Fails unless the binary really can offer SSLv3 and 3DES. Returns its version string."""
    if not os.path.isfile(openssl) or not os.access(openssl, os.X_OK):
        raise RuntimeError(f"legacy OpenSSL not found at {openssl} -- build it with: bash tools/build_legacy_openssl.sh")
    version = subprocess.run([openssl, "version"], capture_output=True, text=True, timeout=15).stdout.strip()
    helptext = subprocess.run([openssl, "s_client", "-help"], capture_output=True, text=True, timeout=15)
    if "-ssl3" not in helptext.stdout + helptext.stderr:
        raise RuntimeError(f"{version} at {openssl} has no SSLv3 support (-ssl3); it is not the legacy build")
    ciphers = subprocess.run([openssl, "ciphers", "-v", DES3], capture_output=True, text=True, timeout=15).stdout
    if "DES-CBC3" not in ciphers:
        raise RuntimeError(f"{version} at {openssl} has no 3DES; it is not the legacy build")
    return version


def make_test_cert(directory):
    """Self-signed RSA-2048 certificate for the local control servers (uses `cryptography`)."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.bd")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2)).sign(key, hashes.SHA256()))
    cpath, kpath = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
    with open(cpath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kpath, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    return cpath, kpath


def free_port(host="127.0.0.1"):
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def local_server(openssl, cert, key, args, host="127.0.0.1", port=None):
    """A throwaway `openssl s_server` on localhost; yields the port."""
    port = port or free_port(host)
    p = subprocess.Popen([openssl, "s_server", "-accept", f"{host}:{port}", "-cert", cert, "-key", key, *args, "-www"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 6
        while True:
            if p.poll() is not None:
                raise RuntimeError(f"s_server exited immediately (args {args})")
            if tcp_reachable(host, port, 0.5):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("s_server did not start")
            time.sleep(0.05)
        yield port
    finally:
        p.terminate()
        try:
            p.wait(3)
        except subprocess.TimeoutExpired:
            p.kill()


def self_test(openssl, timeout=8.0):
    """
    Positive AND negative control of the binary itself, against servers it starts locally:
      SSLv3 server -> accepted and POODLE-exposed | modern server -> SSLv3 refused
      3DES server  -> accepted                    | modern server -> 3DES refused
    Raises RuntimeError on any mismatch, so a broken binary can never produce a silent "0% vulnerable".
    """
    check_capabilities(openssl)
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_test_cert(d)
        legacy_args = ["-ssl3", "-cipher", "ALL:@SECLEVEL=0"]
        des_args = ["-tls1_2", "-cipher", "DES-CBC3-SHA:@SECLEVEL=0"]
        modern_args = ["-no_ssl3", "-no_tls1", "-no_tls1_1", "-cipher", "HIGH:!3DES"]
        results = {}
        with local_server(openssl, cert, key, legacy_args) as p1, \
                local_server(openssl, cert, key, des_args) as p2, \
                local_server(openssl, cert, key, modern_args) as p3:
            results["sslv3_on_legacy"] = probe_sslv3(openssl, "127.0.0.1", p1, timeout)
            results["sslv3_on_modern"] = probe_sslv3(openssl, "127.0.0.1", p3, timeout)
            results["3des_on_3des"] = probe_3des(openssl, "t.bd", "127.0.0.1", p2, timeout)
            results["3des_on_modern"] = probe_3des(openssl, "t.bd", "127.0.0.1", p3, timeout)
    expected = {"sslv3_on_legacy": results["sslv3_on_legacy"]["poodle_exposed"] is True,
                "sslv3_on_modern": results["sslv3_on_modern"]["accepts_sslv3"] is False,
                "3des_on_3des": results["3des_on_3des"]["accepts_3des"] is True,
                "3des_on_modern": results["3des_on_modern"]["accepts_3des"] is False}
    bad = [k for k, ok in expected.items() if not ok]
    if bad:
        raise RuntimeError(f"legacy OpenSSL self-test failed for {bad}: {results}")
    return {k: {"accepts": v.get("accepts_sslv3", v.get("accepts_3des")), "status": v.get("status") or v["offer_all"]["status"]}
            for k, v in results.items()}
