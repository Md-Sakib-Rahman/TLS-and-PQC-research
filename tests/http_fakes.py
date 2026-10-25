"""Local HTTP-over-TLS server for Phase B / b2 tests. Runs on 127.0.0.1, no internet needed."""
import socket
import ssl
import threading


class HTTPTLSServer:
    """Serves one canned HTTP response (status/headers/body) to every request, over TLS using
    the given cert/key PEM files. `close_style` lets tests simulate broken servers."""

    def __init__(self, certfile, keyfile, status=200, reason="OK", headers=None, body=b"hello",
                 close_style="normal", min_version=None):
        self.status, self.reason = status, reason
        self.headers = headers or {}
        self.body = body
        self.close_style = close_style          # normal | no_response | truncate_headers | huge_headers
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        if min_version:
            ctx.minimum_version = min_version
        ctx.set_alpn_protocols(["http/1.1"])
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(50)
        self.port = self.sock.getsockname()[1]
        self.requests = []                       # raw request bytes received, for assertions
        self.lock = threading.Lock()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _response_bytes(self):
        lines = [f"HTTP/1.1 {self.status} {self.reason}\r\n"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}\r\n")
        lines.append(f"Content-Length: {len(self.body)}\r\n\r\n")
        return "".join(lines).encode() + self.body

    def _handle(self, c):
        try:
            tls = self.ctx.wrap_socket(c, server_side=True)
        except Exception:
            c.close()
            return
        try:
            tls.settimeout(3)
            try:
                req = tls.recv(65536)
                with self.lock:
                    self.requests.append(req)
            except Exception:
                pass
            if self.close_style == "no_response":
                pass
            elif self.close_style == "truncate_headers":
                tls.sendall(f"HTTP/1.1 {self.status} {self.reason}\r\nServer: x".encode())  # no blank line
            elif self.close_style == "huge_headers":
                tls.sendall(b"HTTP/1.1 200 OK\r\n" + b"X-Pad: " + b"a" * 200000 + b"\r\n")   # never terminates
            else:
                tls.sendall(self._response_bytes())
        except Exception:
            pass
        finally:
            try:
                tls.close()
            except Exception:
                try:
                    c.close()
                except Exception:
                    pass

    def close(self):
        self.sock.close()


class Blackhole:
    """Accepts TCP, never completes a TLS handshake."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(50)
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


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p