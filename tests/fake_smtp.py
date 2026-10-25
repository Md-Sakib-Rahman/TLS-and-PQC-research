"""Minimal real SMTP server with STARTTLS, for testing protocol mechanics against localhost."""
import socket, ssl, threading, tempfile, os, datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def make_cert(d):
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.test.bd")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2)).sign(key, hashes.SHA256()))
    cpath, kpath = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    with open(cpath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kpath, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cpath, kpath

class FakeSMTP:
    MODES = ("normal", "no_starttls", "starttls_fails_handshake", "no_banner", "drops_after_ehlo", "multiline_ehlo")

    def __init__(self, mode="normal", host="127.0.0.1", port=0):
        self.mode = mode
        self.sock = socket.socket(); self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port)); self.sock.listen(20)
        self.port = self.sock.getsockname()[1]
        self.d = tempfile.mkdtemp()
        self.cert, self.key = make_cert(self.d)
        self.received = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try: c, _ = self.sock.accept()
            except OSError: return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        try:
            c.settimeout(10)
            if self.mode == "no_banner":
                import time; time.sleep(30); return
            c.sendall(b"220 mail.test.bd ESMTP ready\r\n")
            line = c.recv(1024); self.received.append(line)
            if self.mode == "drops_after_ehlo":
                c.close(); return
            if self.mode == "multiline_ehlo":
                c.sendall(b"250-mail.test.bd at your service\r\n250-SIZE 35882577\r\n250 STARTTLS\r\n")
            elif self.mode == "no_starttls":
                c.sendall(b"250-mail.test.bd at your service\r\n250 SIZE 35882577\r\n")
            else:
                c.sendall(b"250-mail.test.bd at your service\r\n250 STARTTLS\r\n")
            if self.mode == "no_starttls":
                line = c.recv(1024); self.received.append(line)
                c.sendall(b"502 5.5.1 Command not implemented\r\n"); return
            line = c.recv(1024); self.received.append(line)   # STARTTLS command
            if self.mode == "starttls_fails_handshake":
                c.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                c.sendall(b"not actually tls garbage bytes"); c.close(); return
            c.sendall(b"220 2.0.0 Ready to start TLS\r\n")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.cert, self.key)
            ts = ctx.wrap_socket(c, server_side=True)
            ts.settimeout(10)
            try:
                line = ts.recv(1024)
                if line.upper().startswith(b"QUIT"): ts.sendall(b"221 2.0.0 Bye\r\n")
            except Exception: pass
            ts.close()
        except Exception as e:
            try: self.received.append(f"ERROR: {e}".encode())
            except Exception: pass

    def close(self):
        self.sock.close()