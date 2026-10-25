#!/usr/bin/env python3
"""
TLS / post-quantum probing engine used by b1_tls_handshake_scan.py.

WHY THIS LIBRARY STACK
  The system OpenSSL on Ubuntu 24.04 (3.0.x) cannot negotiate ML-KEM groups, so Python's
  built-in `ssl` module and `openssl s_client` cannot see post-quantum key exchange.
  The pip `cryptography` package ships its OWN OpenSSL build (3.5+ has ML-KEM). pyOpenSSL
  runs on that build, and two raw OpenSSL calls are made through cryptography's cffi binding:
      SSL_CTX_set1_curves_list  -> which key-exchange groups to offer (and which get key shares: '*')
      SSL_get0_group_name       -> which group the server actually chose
  This reaches into private pyOpenSSL attributes (Context._context, Connection._ssl). A future
  pyOpenSSL release could break that; selftest() fails loudly if it does. Pin the versions.

PROBES PER DOMAIN (all are ordinary TLS handshakes; no application data, no exploits)
  old_versions  Independent check, run for every domain the TCP connection reaches (regardless
                of what the other probes found): client offers ONLY TLS 1.0-1.1 (no 1.2, no 1.3),
                so success proves the server still accepts an old version even when its BEST
                version is higher. The `default`/`classical`/`legacy` probes only ever report a
                server's highest version; without this probe a TLS-1.3-by-default server that
                also still accepts TLS 1.0 for compatibility would look identical to one that
                has removed TLS 1.0 entirely. Skipped only when TCP itself never connected.
  default    Browser-like client: TLS 1.2-1.3, library-default ciphers, groups
             *X25519MLKEM768:*X25519:secp256r1:secp384r1 (two key shares, as current Chrome sends),
             ALPN h2,http/1.1. -> What a normal modern client actually gets today.
  classical  Only if `default` failed after TCP connected: same client, classical groups only
             (ClientHello ~0.3 kB instead of ~1.5 kB). Success here means the server or a
             middlebox is intolerant of the larger post-quantum ClientHello ("pq_intolerant").
  legacy     Only if `classical` also failed at the TLS layer: TLS 1.0-1.3, ALL ciphers,
             security level 0. Success here means the server is only reachable by
             obsolete clients ("legacy_only"). SSLv3 cannot be tested (not in the library).
  pqc_only   Only if the primary handshake was TLS 1.3 with a CLASSICAL group: offer ONLY the
             post-quantum groups the library supports (up to six: three hybrid, three pure ML-KEM).
             Success = server is PQ-capable but does not use it by default.

ACCEPTS_TLS_1_0_OR_1_1 (one per domain, independent of pq_class)
  True     the old_versions probe completed a handshake (TLS 1.0 or 1.1 negotiated)
  False    the old_versions probe got a clear TLS-layer refusal (alert / handshake error)
  None     TCP never connected, or the probe timed out / reset -- no clear answer either way
           (same "don't merge timeout with no" rule used throughout this project)

PQ CLASS (one per domain)
  pq_default               primary handshake negotiated an ML-KEM group
  pq_capable_not_default   default negotiated classical, but pqc_only succeeded
  not_capable              TLS 1.3 server that rejected every offered PQ group (TLS alert)
  no_tls13                 best handshake was TLS 1.2 or older (hybrid PQ groups are TLS 1.3-only)
  unknown                  no handshake succeeded, or pqc_only failed without a clear TLS answer

CERTIFICATE PARSING IS ISOLATED FROM THE HANDSHAKE RESULT
  A successful handshake's status/tls_version/cipher/group is fixed before certificate parsing
  is attempted. If chain retrieval or field parsing raises (cryptography is getting stricter
  about malformed X.509 -- e.g. it currently WARNS on a non-positive certificate serial number,
  RFC 5280 section 4.1.2.2, and says a future release will make that an exception), the domain
  keeps its "ok" handshake status with cert=None or partial, plus an error/warning field --
  it is never downgraded to "error" and does not lose its TLS-level facts. Any warning raised
  while parsing the peer's certificate (malformed Name attributes, non-positive serial numbers,
  etc.) is captured into cert['parse_warnings'] instead of printing, and is itself recorded as
  data: cert['serial_number'] and cert['serial_number_non_positive'] make a "this .bd server's
  certificate violates RFC 5280" finding directly queryable, in the same spirit as Holz et al.
  2011's finding of widespread real-world certificate quality problems.

LIMITATIONS
  - The pre-standard X25519Kyber768Draft00 codepoint is not supported by the library, so a server
    that ONLY speaks that draft is classified not_capable.
  - Certificate chains are validated offline (cryptography's X.509 verifier, certifi/Mozilla roots).
    It does not fetch missing intermediates (browsers may, via AIA), so "incomplete chain" servers
    fail validation here even if some browsers accept them. The error text is recorded.
  - Hostname matching uses SAN dNSNames only (as modern browsers do); CN is recorded, not matched.
"""

import datetime
import hashlib
import select
import socket
import time
import warnings

from cryptography import x509
from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID
from OpenSSL import SSL

_B = Binding()
LIB, FFI = _B.lib, _B.ffi

DEFAULT_GROUPS = "*X25519MLKEM768:*X25519:secp256r1:secp384r1"
CLASSICAL_GROUPS = "*X25519:secp256r1:secp384r1"
PQC_CANDIDATES = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
                  "MLKEM768", "MLKEM1024", "MLKEM512"]
ALPN = [b"h2", b"http/1.1"]


def is_pq_group(name):
    return bool(name) and ("MLKEM" in name.upper() or "KYBER" in name.upper())


def _set_groups(ctx, groups):
    return LIB.SSL_CTX_set1_curves_list(ctx._context, groups.encode()) == 1


def supported_pqc_groups():
    ok = []
    for g in PQC_CANDIDATES:
        ctx = SSL.Context(SSL.TLS_METHOD)
        if _set_groups(ctx, g):
            ok.append(g)
    return ok


def build_contexts(default_groups=DEFAULT_GROUPS, classical_groups=CLASSICAL_GROUPS, pqc_groups=None):
    """One SSL_CTX per probe type, created once and shared (read-only) by all threads."""
    pqc_groups = pqc_groups if pqc_groups is not None else supported_pqc_groups()

    def ctx(groups, legacy=False):
        c = SSL.Context(SSL.TLS_METHOD)
        c.set_verify(SSL.VERIFY_NONE, lambda *a: True)        # record what is offered; validate offline
        if legacy:
            c.set_min_proto_version(SSL.TLS1_VERSION)
            c.set_cipher_list(b"ALL:@SECLEVEL=0")
        else:
            c.set_min_proto_version(SSL.TLS1_2_VERSION)
        if groups and not _set_groups(c, groups):
            raise RuntimeError(f"library rejected group list: {groups}")
        c.set_alpn_protos(ALPN)
        return c

    def old_versions_ctx():
        c = SSL.Context(SSL.TLS_METHOD)
        c.set_verify(SSL.VERIFY_NONE, lambda *a: True)
        c.set_min_proto_version(SSL.TLS1_VERSION)
        c.set_max_proto_version(SSL.TLS1_1_VERSION)          # TLS 1.0-1.1 ONLY: never offer 1.2/1.3
        c.set_cipher_list(b"ALL:@SECLEVEL=0")
        c.set_alpn_protos(ALPN)
        return c

    return {"default": ctx(default_groups), "classical": ctx(classical_groups),
            "legacy": ctx(classical_groups, legacy=True),
            "pqc_only": ctx(":".join(pqc_groups)) if pqc_groups else None,
            "old_versions": old_versions_ctx(),
            "_groups": {"default": default_groups, "classical": classical_groups,
                        "legacy": classical_groups, "pqc_only": ":".join(pqc_groups),
                        "old_versions": "TLS1.0-1.1 only, ALL:@SECLEVEL=0"}}


def selftest():
    """Raises if the library cannot do what the scan depends on. Returns version info."""
    import OpenSSL, cryptography
    if not getattr(LIB, "Cryptography_HAS_SSL_GET0_GROUP_NAME", 0):
        raise RuntimeError("SSL_get0_group_name unavailable -- upgrade cryptography")
    pq = supported_pqc_groups()
    if "X25519MLKEM768" not in pq:
        raise RuntimeError(f"bundled OpenSSL lacks X25519MLKEM768 (has {pq}) -- pip install -U cryptography pyopenssl")
    build_contexts()                                             # raises on any bad group list
    return {"pyopenssl": OpenSSL.__version__, "cryptography": cryptography.__version__,
            "bundled_openssl": SSL.SSLeay_version(SSL.SSLEAY_VERSION).decode(), "pqc_groups_offered": pq}


# ---------------------------------------------------------------- one handshake

TRANSPORT_ERRORS = ("timeout", "connect_refused", "connect_timeout", "connect_error")


def _classify_ssl_error(e):
    text = str(e)
    if "alert" in text.lower():
        return "tls_alert"
    return "tls_error"


def handshake(ctx, host, ip, port=443, timeout=10.0):
    """
    One TLS handshake with SNI=host to ip:port. Never raises.
    Returns (result_dict, peer_chain_or_None). result_dict['status'] is one of:
      ok | tls_alert | tls_error | timeout | connect_refused | connect_timeout | connect_error | error
    """
    t0 = time.monotonic()
    deadline = t0 + timeout
    res = {"status": "error"}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return {"status": "connect_refused"}, None
    except (socket.timeout, TimeoutError):
        return {"status": "connect_timeout"}, None
    except OSError as e:
        return {"status": "connect_error", "error": type(e).__name__}, None
    conn = None
    try:
        sock.setblocking(False)
        conn = SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(host.encode("idna"))
        conn.set_connect_state()
        while True:
            try:
                conn.do_handshake()
                break
            except SSL.WantReadError:
                r, _, _ = select.select([sock], [], [], max(0.0, deadline - time.monotonic()))
            except SSL.WantWriteError:
                _, r, _ = select.select([], [sock], [], max(0.0, deadline - time.monotonic()))
            if not r and time.monotonic() >= deadline:
                return {"status": "timeout"}, None
        # Handshake succeeded: fix the TLS-level result NOW. Certificate handling below can
        # raise (cryptography's own parsing warnings can become exceptions in a future release)
        # without that ever turning this "ok" result into a lost/"error" record.
        p = LIB.SSL_get0_group_name(conn._ssl)
        alpn = conn.get_alpn_proto_negotiated()
        res = {"status": "ok", "tls_version": conn.get_protocol_version_name(),
               "cipher": conn.get_cipher_name(),
               "group": FFI.string(p).decode() if p != FFI.NULL else None,
               "alpn": alpn.decode() if alpn else None,
               "ms": round((time.monotonic() - t0) * 1000)}
        chain = None
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                chain = conn.get_peer_cert_chain(as_cryptography=True) if _chain_kw_supported() else \
                    [c.to_cryptography() for c in (conn.get_peer_cert_chain() or [])]
            except Exception as e:
                res["chain_error"] = f"{type(e).__name__}: {e}"[:200]
        if caught:
            res["chain_parse_warnings"] = [str(w.message) for w in caught]
        return res, chain
    except SSL.SysCallError as e:
        return {"status": "tls_error", "error": f"syscall: {e.args[-1] if e.args else ''}"[:200]}, None
    except SSL.ZeroReturnError:
        return {"status": "tls_error", "error": "connection closed during handshake"}, None
    except SSL.Error as e:
        return {"status": _classify_ssl_error(e), "error": str(e)[:200]}, None
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"[:200]}, None
    finally:
        if conn is not None:
            try:
                conn.shutdown()
            except Exception:
                pass
        sock.close()


_CHAIN_KW = None


def _chain_kw_supported():
    global _CHAIN_KW
    if _CHAIN_KW is None:
        import inspect
        try:
            _CHAIN_KW = "as_cryptography" in inspect.signature(SSL.Connection.get_peer_cert_chain).parameters
        except (TypeError, ValueError):
            _CHAIN_KW = False
    return _CHAIN_KW


# ---------------------------------------------------------------- certificates

def load_trust_store_with_info(pem_path=None):
    """Loads roots one by one so a single malformed root (cryptography is getting stricter,
    e.g. about non-positive serial numbers) cannot crash the scan. Returns (Store, info)."""
    import re
    import warnings
    from cryptography.x509.verification import Store
    if pem_path is None:
        import certifi
        pem_path = certifi.where()
    with open(pem_path, "rb") as f:
        blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", f.read(), re.S)
    certs, skipped, warned = [], 0, 0
    for b in blocks:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                certs.append(x509.load_pem_x509_certificate(b))
            except Exception:
                skipped += 1
            warned += bool(w)
    if not certs:
        raise RuntimeError(f"no usable root certificates in {pem_path}")
    return Store(certs), {"path": pem_path, "roots_loaded": len(certs), "roots_skipped": skipped,
                          "roots_with_parse_warnings": warned}


def load_trust_store(pem_path=None):
    return load_trust_store_with_info(pem_path)[0]


def _name_attr(name, oid):
    try:
        v = name.get_attributes_for_oid(oid)
        return v[0].value if v else None
    except Exception:
        return None


def _key_info(pub):
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size, None
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.key_size, pub.curve.name
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 456, None
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size, None
    return type(pub).__name__, None, None


def hostname_matches(host, dns_names):
    host = host.lower().rstrip(".")
    for n in dns_names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == n[2:] and host.split(".", 1)[0]:
                return True
    return False


def analyze_chain(host, chain, store, now=None):
    """Certificate facts from the leaf + offline validation of the presented chain.
    Any warning cryptography raises while parsing the peer's certificate (malformed Name
    attributes, non-positive serial numbers, etc.) is captured into out['parse_warnings']
    rather than printed, and the serial number / its RFC 5280 compliance is recorded as data
    regardless -- see the module docstring."""
    if not chain:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    leaf = chain[0]
    out = {"chain_len": len(chain)}
    caught = []
    try:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans = []
            ktype, kbits, curve = _key_info(leaf.public_key())
            try:
                sig_hash = leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else None
            except Exception:
                sig_hash = None
            serial = leaf.serial_number
            subject_cn = _name_attr(leaf.subject, NameOID.COMMON_NAME)
            issuer_cn = _name_attr(leaf.issuer, NameOID.COMMON_NAME)
            issuer_o = _name_attr(leaf.issuer, NameOID.ORGANIZATION_NAME)
            sig_alg = getattr(leaf.signature_algorithm_oid, "_name", None) or leaf.signature_algorithm_oid.dotted_string
            sig_alg_oid = leaf.signature_algorithm_oid.dotted_string
            nb, na = leaf.not_valid_before_utc, leaf.not_valid_after_utc
            self_signed = leaf.issuer == leaf.subject
            leaf_sha256 = leaf.fingerprint(hashes.SHA256()).hex()
        caught = [str(x.message) for x in w]
        out.update({
            "subject_cn": subject_cn, "issuer_cn": issuer_cn, "issuer_o": issuer_o,
            "sig_alg": sig_alg, "sig_alg_oid": sig_alg_oid, "sig_hash": sig_hash,
            "key_type": ktype, "key_bits": kbits, "key_curve": curve,
            "not_before": nb.isoformat(), "not_after": na.isoformat(),
            "expired": na < now, "not_yet_valid": nb > now,
            "san_count": len(sans), "hostname_match": hostname_matches(host, sans),
            "self_signed": self_signed,
            "leaf_sha256": leaf_sha256,
            "serial_number": str(serial),                       # str: can exceed JSON-safe int range
            "serial_number_non_positive": serial <= 0,           # RFC 5280 section 4.1.2.2 violation
        })
    except Exception as e:
        out["parse_error"] = f"{type(e).__name__}: {e}"[:200]
    if caught:
        out["parse_warnings"] = caught
    try:
        out["chain_pem"] = [c.public_bytes(serialization.Encoding.PEM).decode() for c in chain]
    except Exception:
        out["chain_pem"] = None
    # offline validation against the trust store (chain + hostname + validity at scan time)
    try:
        from cryptography.x509.verification import PolicyBuilder
        verifier = PolicyBuilder().store(store).time(now).build_server_verifier(x509.DNSName(host))
        verifier.verify(leaf, chain[1:])
        out["trusted"], out["trust_error"] = True, None
    except Exception as e:
        out["trusted"], out["trust_error"] = False, f"{type(e).__name__}: {e}"[:300]
    return out


# ---------------------------------------------------------------- per domain

def pq_class(primary, pqc_probe):
    if primary is None:
        return "unknown"
    if is_pq_group(primary.get("group")):
        return "pq_default"
    if primary.get("tls_version") != "TLSv1.3":
        return "no_tls13"
    if pqc_probe is None or pqc_probe.get("status") == "skipped":
        return "unknown"
    if pqc_probe["status"] == "ok" and is_pq_group(pqc_probe.get("group")):
        return "pq_capable_not_default"
    if pqc_probe["status"] == "tls_alert":
        return "not_capable"
    return "unknown"                                  # timeout / reset / odd error: no clear answer


def scan_domain(host, ip, ctxs, store, port=443, timeout=10.0, gate=None):
    """
    Runs the probe sequence for one domain. `gate` is a context-manager factory used around each
    connection (per-IP concurrency cap + global rate limit); None = no gating (tests).
    """
    def run(name):
        if gate:
            with gate(ip):
                return handshake(ctxs[name], host, ip, port, timeout)
        return handshake(ctxs[name], host, ip, port, timeout)

    probes, chain = {}, None
    probes["default"], chain = run("default")
    primary_name = "default" if probes["default"]["status"] == "ok" else None
    tcp_failed = probes["default"]["status"].startswith("connect_")

    if primary_name is None and not tcp_failed:
        probes["classical"], chain = run("classical")
        if probes["classical"]["status"] == "ok":
            primary_name = "classical"
        elif probes["classical"]["status"] in ("tls_alert", "tls_error"):
            probes["legacy"], chain = run("legacy")
            if probes["legacy"]["status"] == "ok":
                primary_name = "legacy"

    primary = probes[primary_name] if primary_name else None
    if primary and primary.get("tls_version") == "TLSv1.3" and not is_pq_group(primary.get("group")) and ctxs.get("pqc_only"):
        probes["pqc_only"], _ = run("pqc_only")
    else:
        reason = ("no_successful_handshake" if not primary else
                  "already_pq" if is_pq_group(primary.get("group")) else
                  "not_tls13" if primary.get("tls_version") != "TLSv1.3" else "no_pqc_groups_available")
        probes["pqc_only"] = {"status": "skipped", "reason": reason}

    if tcp_failed:
        probes["old_versions"] = {"status": "skipped", "reason": "tcp_failed"}
    else:
        probes["old_versions"], _ = run("old_versions")

    ov = probes["old_versions"]
    if ov["status"] == "ok":
        accepts_old = True
    elif ov["status"] in ("tls_alert", "tls_error"):
        accepts_old = False
    else:                                            # skipped / timeout / connect_* / error: no clear answer
        accepts_old = None

    if primary:
        status = "ok"
    elif tcp_failed:
        status = "connect_failed"
    else:
        last = probes.get("legacy") or probes.get("classical") or probes["default"]
        status = "timeout" if last["status"] == "timeout" else last["status"]

    return {
        "accepts_tls_1_0_or_1_1": accepts_old,
        "domain": host, "ip": ip, "status": status, "primary_probe": primary_name, "probes": probes,
        "tls_version": primary.get("tls_version") if primary else None,
        "cipher": primary.get("cipher") if primary else None,
        "group": primary.get("group") if primary else None,
        "alpn": primary.get("alpn") if primary else None,
        "pq_class": pq_class(primary, probes.get("pqc_only")),
        "pq_intolerant": (primary_name == "classical") if primary else None,
        "legacy_only": primary_name == "legacy",
        "cert": analyze_chain(host, chain, store) if chain else None,
    }


# ---------------------------------------------------------------- control

def control_check(hosts, ctxs, store, port=443, timeout=10.0, resolve=None):
    """
    Positive control: at least one host known to serve hybrid PQ by default must negotiate an
    ML-KEM group with a certificate that validates. Fails if the library, the network path
    (e.g. a middlebox dropping large ClientHellos) or an intercepting proxy would corrupt results.
    """
    resolve = resolve or (lambda h: socket.getaddrinfo(h, port, type=socket.SOCK_STREAM)[0][4][0])
    results, ok = {}, False
    for h in hosts:
        try:
            ip = resolve(h)
        except Exception as e:
            results[h] = {"status": "resolve_failed", "error": type(e).__name__}
            continue
        r, chain = handshake(ctxs["default"], h, ip, port, timeout)
        cert = analyze_chain(h, chain, store) if chain else None
        r["trusted"] = cert["trusted"] if cert else None
        results[h] = r
        ok = ok or (r["status"] == "ok" and is_pq_group(r.get("group")) and r["trusted"] is True)
    return results, ok