#!/usr/bin/env python3
"""
Local loopback self-test for the patched smtp_probe.py -- no internet access needed.

Spins up a minimal fake STARTTLS server on 127.0.0.1 (plaintext banner/EHLO/STARTTLS exchange,
then a real TLS handshake using the same pyOpenSSL/bundled-OpenSSL stack as the patched probe,
with PQ groups enabled on both ends), then runs smtp_probe.probe_smtp() against it exactly the
way c4_smtp_scan.py would. Verifies: handshake completes, `group` is captured and is a PQ group,
tls_version/cipher are captured, status ends "ok".
"""
import datetime
import socket
import select
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import SSL, crypto

import smtp_probe as S


def make_selfsigned_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert.public_bytes(serialization.Encoding.PEM))
    return pkey, x509_cert


def server_thread(sock, pkey, cert, ready_evt):
    conn_sock, _ = sock.accept()
    conn_sock.setblocking(True)
    conn_sock.sendall(b"220 localhost ESMTP selftest\r\n")
    data = conn_sock.recv(4096)
    assert b"EHLO" in data, data
    conn_sock.sendall(b"250-localhost\r\n250 STARTTLS\r\n")
    data = conn_sock.recv(4096)
    assert b"STARTTLS" in data, data
    conn_sock.sendall(b"220 Go ahead\r\n")

    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.use_privatekey(pkey)
    ctx.use_certificate(cert)
    S._set_groups(ctx, S.DEFAULT_GROUPS)   # server also offers/accepts PQ groups
    conn_sock.setblocking(False)
    tls_conn = SSL.Connection(ctx, conn_sock)
    tls_conn.set_accept_state()
    deadline = time.monotonic() + 10
    while True:
        try:
            tls_conn.do_handshake()
            break
        except SSL.WantReadError:
            select.select([conn_sock], [], [], max(0.0, deadline - time.monotonic()))
        except SSL.WantWriteError:
            select.select([], [conn_sock], [], max(0.0, deadline - time.monotonic()))
    try:
        select.select([conn_sock], [], [], 5.0)
        tls_conn.recv(200)   # the client's best-effort QUIT
    except Exception:
        pass
    try:
        tls_conn.shutdown()
    except Exception:
        pass
    conn_sock.close()


def main():
    pkey, cert = make_selfsigned_cert()
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", 0))
    port = srv_sock.getsockname()[1]
    srv_sock.listen(1)

    t = threading.Thread(target=server_thread, args=(srv_sock, pkey, cert, None), daemon=True)
    t.start()

    r = S.probe_smtp("localhost", "127.0.0.1", "selftest.invalid", port=port, timeout=10.0)
    t.join(timeout=5)
    srv_sock.close()

    print(r)
    assert r["status"] == "ok", f"expected status=ok, got {r}"
    assert r.get("tls_version") == "TLSv1.3", f"expected TLSv1.3, got {r.get('tls_version')}"
    assert S.is_pq_group(r.get("group")), f"expected a PQ group, got {r.get('group')}"
    print(f"\nSELF-TEST PASSED: status=ok, tls_version={r['tls_version']}, "
          f"group={r['group']} (PQ), cipher={r['cipher']}")


if __name__ == "__main__":
    main()