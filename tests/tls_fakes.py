"""Local TLS servers and helpers for Phase B tests. Everything runs on 127.0.0.1."""
import datetime
import socket
import threading
import time

from cryptography import x509
from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.name import NameAttribute
from OpenSSL import SSL, crypto

LIB = Binding().lib
NOW = lambda: datetime.datetime.now(datetime.timezone.utc)


def make_ca(cn="Test Root CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(NOW() - datetime.timedelta(days=1))
            .not_valid_after(NOW() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_leaf(ca_key, ca_cert, names, rsa_bits=None, expired=False, self_signed=False):
    key = rsa.generate_private_key(65537, rsa_bits) if rsa_bits else ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    issuer, skey = (subj, key) if self_signed else (ca_cert.subject, ca_key)
    nb = NOW() - datetime.timedelta(days=400 if expired else 1)
    na = NOW() - datetime.timedelta(days=10) if expired else NOW() + datetime.timedelta(days=90)
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(skey.public_key()), critical=False))
    if not self_signed:
        b = b.add_extension(x509.KeyUsage(True, False, rsa_bits is not None, False, False, False, False, False, False), critical=True)
    return key, b.sign(skey, hashes.SHA256())


def make_leaf_with_bad_country_code(ca_key, ca_cert, names):
    """A real-world quirk: a Name attribute (here C=, which RFC 5280 requires to be exactly
    2 chars) with an out-of-range length. cryptography parses this from the wire with a
    warning, not an error, so it is a genuine thing a live server can present."""
    key = ec.generate_private_key(ec.SECP256R1())
    bad_c = NameAttribute(NameOID.COUNTRY_NAME, "", _validate=False)
    subj = x509.Name([bad_c, x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = NOW()
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(ca_cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=90))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    return key, b.sign(ca_key, hashes.SHA256())


def write_pem(path, certs):
    with open(path, "wb") as f:
        for c in certs:
            f.write(c.public_bytes(serialization.Encoding.PEM))


class TLSServer:
    """Configurable TLS server. Tracks peak concurrent connections."""

    def __init__(self, key, cert, groups=None, min_v=None, max_v=None, server_pref=False, seclevel0=False, hold=0.0):
        ctx = SSL.Context(SSL.TLS_METHOD)
        if seclevel0:
            ctx.set_cipher_list(b"ALL:@SECLEVEL=0")
        try:
            ctx.use_privatekey(key)
            ctx.use_certificate(cert)
        except TypeError:                                   # older pyOpenSSL: wrap explicitly
            ctx.use_privatekey(crypto.PKey.from_cryptography_key(key))
            ctx.use_certificate(crypto.X509.from_cryptography(cert))
        if groups:
            assert LIB.SSL_CTX_set1_curves_list(ctx._context, groups.encode()) == 1
        if min_v:
            ctx.set_min_proto_version(min_v)
        if max_v:
            ctx.set_max_proto_version(max_v)
        if server_pref:
            ctx.set_options(SSL.OP_CIPHER_SERVER_PREFERENCE)
        self.ctx, self.hold = ctx, hold
        self.active = self.peak = self.accepted = 0
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(100)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        with self.lock:
            self.active += 1
            self.accepted += 1
            self.peak = max(self.peak, self.active)
        try:
            if self.hold:
                time.sleep(self.hold)
            conn = SSL.Connection(self.ctx, c)
            conn.set_accept_state()
            conn.do_handshake()
            try:
                conn.recv(1)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            with self.lock:
                self.active -= 1
            try:
                c.close()
            except Exception:
                pass

    def close(self):
        self.sock.close()


class Blackhole:
    """Accepts TCP, never answers (handshake timeout)."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(100)
        self.port = self.sock.getsockname()[1]
        self.held = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
                self.held.append(c)
            except OSError:
                return

    def close(self):
        self.sock.close()
        for c in self.held:
            c.close()


class DropLargeClientHello:
    """Middlebox simulation: silently stalls connections whose first TLS record exceeds `limit` bytes,
    forwards everything else to `backend_port`."""

    def __init__(self, backend_port, limit=1000):
        self.backend, self.limit = backend_port, limit
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(100)
        self.port = self.sock.getsockname()[1]
        self.held = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, cs):
        cs.settimeout(3)
        head = b""
        try:
            while len(head) < 5:
                chunk = cs.recv(5 - len(head))
                if not chunk:
                    cs.close()
                    return
                head += chunk
        except Exception:
            cs.close()
            return
        if int.from_bytes(head[3:5], "big") > self.limit:
            self.held.append(cs)                         # stall, like a broken middlebox
            return
        bs = socket.create_connection(("127.0.0.1", self.backend))
        bs.sendall(head)
        cs.settimeout(None)

        def pump(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    b.sendall(d)
            except Exception:
                pass
            finally:
                for x in (a, b):
                    try:
                        x.close()
                    except Exception:
                        pass
        threading.Thread(target=pump, args=(cs, bs), daemon=True).start()
        threading.Thread(target=pump, args=(bs, cs), daemon=True).start()

    def close(self):
        self.sock.close()
        for c in self.held:
            c.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p