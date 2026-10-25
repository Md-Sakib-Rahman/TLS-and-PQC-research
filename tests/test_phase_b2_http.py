#!/usr/bin/env python3
"""
Tests for Phase B, step 2 (b2 HTTP header collection). Real HTTP-over-TLS requests against
local servers on 127.0.0.1 -- no internet needed. Run from project root:
    python tests/test_phase_b2_http.py
"""

import csv
import datetime
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)
sys.path.insert(0, HERE)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import http_fakes as F
from measurement.phase_b_tls import http_probe as H

TMP = tempfile.mkdtemp()
_key = ec.generate_private_key(ec.SECP256R1())
_now = datetime.datetime.now(datetime.timezone.utc)
_cert = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.bd")]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.bd")]))
         .public_key(_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(_now - datetime.timedelta(days=1)).not_valid_after(_now + datetime.timedelta(days=90))
         .sign(_key, hashes.SHA256()))
CERTFILE, KEYFILE = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem")
with open(CERTFILE, "wb") as f:
    f.write(_cert.public_bytes(serialization.Encoding.PEM))
with open(KEYFILE, "wb") as f:
    f.write(_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption()))
CTX = H.build_context()


def probe(port, **kw):
    return H.probe_domain("test.bd", "127.0.0.1", port=port, timeout=3, ctx=CTX, **kw)


class Srv:
    def __init__(self, **kw):
        self.s = F.HTTPTLSServer(CERTFILE, KEYFILE, **kw)

    def __enter__(self):
        return self.s

    def __exit__(self, *a):
        self.s.close()


class TestResponseParsing(unittest.TestCase):
    def test_basic_response(self):
        with Srv(headers={"Server": "nginx"}) as s:
            r = probe(s.port)
        self.assertEqual((r["status"], r["status_code"], r["http_version"]), ("ok", 200, "1.1"))
        self.assertEqual(r["headers"]["server"], "nginx")
        self.assertIn("GET / HTTP/1.1", s.requests[0].decode())
        self.assertIn("Host: test.bd", s.requests[0].decode())
        self.assertIn("Connection: close", s.requests[0].decode())

    def test_custom_user_agent_is_sent(self):
        with Srv() as s:
            probe(s.port, user_agent="my-scanner/9 (+http://example.test)")
        self.assertIn("my-scanner/9", s.requests[0].decode())

    def test_repeated_headers_are_joined(self):
        # Set-Cookie commonly repeats; simulate via raw header injection through 'headers' dict
        # (dict can't hold two Set-Cookie keys, so test the joiner at the parser level directly)
        head = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n"
        r = H.parse_response(head)
        self.assertEqual(r["headers"]["set-cookie"], "a=1; b=2")

    def test_status_code_and_reason_captured(self):
        with Srv(status=503, reason="Service Unavailable") as s:
            r = probe(s.port)
        self.assertEqual((r["status_code"], r["reason"]), (503, "Service Unavailable"))

    def test_redirect_recorded_not_followed(self):
        with Srv(status=301, reason="Moved Permanently", headers={"Location": "https://www.test.bd/"}) as s:
            r = probe(s.port)
        self.assertEqual(r["status_code"], 301)
        self.assertEqual(r["headers"]["location"], "https://www.test.bd/")
        self.assertEqual(len([req for req in s.requests]), 1)      # exactly one request: not followed

    def test_bad_status_line(self):
        head = b"NOT AN HTTP RESPONSE\r\nServer: x\r\n"
        self.assertEqual(H.parse_response(head)["status"], "bad_status_line")


class TestHSTS(unittest.TestCase):
    def test_absent(self):
        self.assertEqual(H.parse_hsts({}), {"present": False})

    def test_present_full(self):
        h = {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}
        r = H.parse_hsts(h)
        self.assertEqual(r, {"present": True, "raw": h["strict-transport-security"], "max_age": 31536000,
                             "include_subdomains": True, "preload": True})

    def test_present_bare_max_age_only(self):
        r = H.parse_hsts({"strict-transport-security": "max-age=3600"})
        self.assertEqual((r["present"], r["max_age"], r["include_subdomains"], r["preload"]),
                         (True, 3600, False, False))

    def test_case_insensitive_directives(self):
        r = H.parse_hsts({"strict-transport-security": "Max-Age=100; IncludeSubDomains"})
        self.assertEqual((r["max_age"], r["include_subdomains"]), (100, True))

    def test_end_to_end_real_server(self):
        with Srv(headers={"Strict-Transport-Security": "max-age=100"}) as s:
            r = probe(s.port)
        self.assertEqual(r["hsts"], {"present": True, "raw": "max-age=100", "max_age": 100,
                                     "include_subdomains": False, "preload": False})


class TestWAFDetection(unittest.TestCase):
    def test_no_signature(self):
        r = H.detect_waf({"server": "nginx", "content-type": "text/html"})
        self.assertEqual(r, {"detected": False, "vendors": [], "evidence": []})

    def test_cloudflare_via_server_header(self):
        r = H.detect_waf({"server": "cloudflare"})
        self.assertTrue(r["detected"])
        self.assertEqual(r["vendors"], ["Cloudflare"])

    def test_cloudflare_via_cf_ray_even_without_server_header(self):
        r = H.detect_waf({"server": "nginx", "cf-ray": "abc123-DAC"})
        self.assertEqual(r["vendors"], ["Cloudflare"])

    def test_incapsula_via_cookie(self):
        r = H.detect_waf({"set-cookie": "incap_ses_123_456=xyz; path=/"})
        self.assertEqual(r["vendors"], ["Imperva/Incapsula"])

    def test_multiple_vendors_can_coexist(self):
        r = H.detect_waf({"server": "cloudflare", "x-amz-cf-id": "abc"})
        self.assertEqual(r["vendors"], ["AWS CloudFront", "Cloudflare"])

    def test_false_positive_guard_plain_nginx(self):
        # A plain, unremarkable origin server must never match any signature.
        r = H.detect_waf({"server": "nginx/1.24.0", "date": "x", "content-type": "text/html"})
        self.assertFalse(r["detected"])

    def test_end_to_end_real_server(self):
        with Srv(headers={"Server": "cloudflare", "CF-RAY": "abc-DAC"}) as s:
            r = probe(s.port)
        self.assertTrue(r["waf"]["detected"])
        self.assertIn("Cloudflare", r["waf"]["vendors"])


class TestFailureModes(unittest.TestCase):
    def test_connect_refused(self):
        self.assertEqual(H.fetch_headers("test.bd", "127.0.0.1", F.free_port(), timeout=2, ctx=CTX)["status"],
                         "connect_refused")

    def test_tls_never_completes(self):
        bh = F.Blackhole()
        try:
            r = H.fetch_headers("test.bd", "127.0.0.1", bh.port, timeout=1, ctx=CTX)
        finally:
            bh.close()
        self.assertIn(r["status"], ("timeout", "tls_error"))

    def test_server_closes_without_responding(self):
        with Srv(close_style="no_response") as s:
            r = probe(s.port)
        self.assertIn(r["status"], ("timeout", "empty_response", "tls_error"))
        self.assertIsNone(r["hsts"])
        self.assertIsNone(r["waf"])

    def test_truncated_headers_no_blank_line(self):
        """The server sends a real status line and one header but closes WITHOUT the blank
        line that ends the headers. This must never be parsed as a complete 'ok' response --
        that would silently treat a truncated, arbitrary-length fragment as ground truth."""
        with Srv(close_style="truncate_headers") as s:
            r = probe(s.port)
        self.assertEqual(r["status"], "incomplete_response")
        self.assertIsNone(r["hsts"])
        self.assertIsNone(r["waf"])

    def test_huge_header_stream_is_bounded(self):
        """A server that never sends the terminator (or sends it past max_bytes) must not hang,
        consume unbounded memory, or get parsed as 'ok' from a truncated mid-value fragment."""
        with Srv(close_style="huge_headers") as s:
            r = H.fetch_headers("test.bd", "127.0.0.1", s.port, timeout=3, ctx=CTX, max_bytes=4096)
        self.assertEqual(r["status"], "headers_too_large")

    def test_tls10_only_server_reachable_with_low_floor_context(self):
        with Srv(min_version=ssl.TLSVersion.TLSv1, headers={"Server": "old-iis"}) as s:
            r = probe(s.port)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["headers"]["server"], "old-iis")


    def test_large_but_complete_response_still_parses(self):
        """Regression guard: the fix above must not make ordinary large (but complete, properly
        terminated) responses fail."""
        big_value = "x" * 3000
        with Srv(headers={"X-Big": big_value}, body=b"y" * 3000) as s:
            r = H.fetch_headers("test.bd", "127.0.0.1", s.port, timeout=3, ctx=CTX, max_bytes=8192)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["headers"]["x-big"], big_value)


class TestControlCheck(unittest.TestCase):
    def test_passes_when_signature_present(self):
        def resolve(h):
            return "127.0.0.1"
        with Srv(headers={"Server": "cloudflare"}) as s:
            F.HTTPTLSServer  # noqa: keep import used
            results, ok = H.control_check(["test.bd"], CTX, port=s.port, timeout=3, resolve=resolve)
        self.assertTrue(ok)

    def test_fails_when_no_signature(self):
        def resolve(h):
            return "127.0.0.1"
        with Srv(headers={"Server": "nginx"}) as s:
            results, ok = H.control_check(["test.bd"], CTX, port=s.port, timeout=3, resolve=resolve)
        self.assertFalse(ok)

    def test_resolve_failure(self):
        def boom(h):
            raise OSError("no dns")
        results, ok = H.control_check(["x.invalid"], CTX, resolve=boom)
        self.assertFalse(ok)
        self.assertEqual(results["x.invalid"]["status"], "resolve_failed")


class TestPoliteness(unittest.TestCase):
    def test_gate_shared_with_b1_caps_per_ip(self):
        import threading
        import contextlib
        from concurrent.futures import ThreadPoolExecutor
        from measurement.common.net_utils import Gate

        with Srv() as s:
            gate = Gate(2, 0)
            active, peak, lock = [0], [0], threading.Lock()

            def one(_):
                with gate("127.0.0.1"):
                    with lock:
                        active[0] += 1
                        peak[0] = max(peak[0], active[0])
                    r = probe(s.port)
                    with lock:
                        active[0] -= 1
                    return r
            with ThreadPoolExecutor(10) as pool:
                results = list(pool.map(one, range(10)))
        self.assertTrue(all(r["status"] == "ok" for r in results))
        self.assertLessEqual(peak[0], 2)


class TestEndToEnd(unittest.TestCase):
    """b2's real main() in a temp copy of the project, against one local server."""

    DOMAINS = ["test.bd", "other.bd"]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.proj = os.path.join(cls.tmp, "proj")
        for sub in ("measurement", "tests"):
            shutil.copytree(os.path.join(BASE, sub), os.path.join(cls.proj, sub),
                            ignore=shutil.ignore_patterns("__pycache__"))
        cls.srv = F.HTTPTLSServer(CERTFILE, KEYFILE, headers={"Strict-Transport-Security": "max-age=1",
                                                               "Server": "cloudflare"})
        run = os.path.join(cls.proj, "data", "measurement", "runs", "run_test", "raw")
        os.makedirs(run)
        os.makedirs(os.path.join(cls.proj, "data", "measurement", "processed"))
        with open(os.path.join(run, "port443.jsonl"), "w") as f:
            for d in cls.DOMAINS:
                f.write(json.dumps({"domain": d, "port443": "open"}) + "\n")
        with open(os.path.join(cls.proj, "data", "measurement", "processed", "live_domains.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "sector", "category", "tier", "ip", "family"])
            for d in cls.DOMAINS:
                w.writerow([d, "x", "x", "verified", "127.0.0.1", "4"])

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def b2(self, *extra):
        cmd = [sys.executable, "tests/run_b2_with_fakes.py", str(self.srv.port), "--run-id", "run_test",
               "--skip-control", "--skip-ua-check", *extra]
        return subprocess.run(cmd, cwd=self.proj, capture_output=True, text=True)

    def test_full_run_and_resume(self):
        p = self.b2()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        out = os.path.join(self.proj, "data", "measurement", "runs", "run_test", "raw", "http.jsonl")
        with open(out) as f:
            recs = [json.loads(l) for l in f]
        self.assertEqual(sorted(r["domain"] for r in recs), sorted(self.DOMAINS))
        self.assertTrue(all(r["status"] == "ok" and r["hsts"]["present"] and "Cloudflare" in r["waf"]["vendors"]
                            for r in recs))
        p = self.b2()
        self.assertIn("to do 0", p.stdout)

    def test_ua_placeholder_blocks_run_without_skip_flag(self):
        cmd = [sys.executable, "tests/run_b2_with_fakes.py", str(self.srv.port), "--run-id", "run_test"]
        p = subprocess.run(cmd, cwd=self.proj, capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("placeholder", p.stdout + p.stderr)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)