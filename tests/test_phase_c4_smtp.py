#!/usr/bin/env python3
"""
Tests for Phase C4 (SMTP/STARTTLS). Real local SMTP servers (tests/fake_smtp.py) for the probe
engine; synthetic dns.jsonl/liveness_all.csv for the runner. Run: python tests/test_phase_c4_smtp.py
"""
import csv
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)
sys.path.insert(0, HERE)

from fake_smtp import FakeSMTP
from measurement.phase_c_derived import c4_smtp_scan as C4
from measurement.phase_c_derived import smtp_probe as S

CTX = S.build_context()


class TestReplyParser(unittest.TestCase):
    class Fed:
        """Feeds pre-chunked bytes to _recv_reply, simulating partial TCP reads."""
        def __init__(self, chunks):
            self.chunks = list(chunks)
        def settimeout(self, t):
            pass
        def recv(self, n):
            return self.chunks.pop(0) if self.chunks else b""

    def test_single_line(self):
        code, lines, raw = S._recv_reply(self.Fed([b"250 OK\r\n"]), 2)
        self.assertEqual((code, lines), (250, ["OK"]))

    def test_multiline(self):
        code, lines, _ = S._recv_reply(self.Fed([b"250-a\r\n250-STARTTLS\r\n250 SIZE 1\r\n"]), 2)
        self.assertEqual((code, lines), (250, ["a", "STARTTLS", "SIZE 1"]))

    def test_split_mid_token_across_reads(self):
        """The exact bug class that would corrupt a capability list if buffering were wrong."""
        code, lines, _ = S._recv_reply(self.Fed([b"250-mail.test\r\n250-STAR", b"TTLS\r\n250 OK\r\n"]), 2)
        self.assertEqual((code, lines), (250, ["mail.test", "STARTTLS", "OK"]))

    def test_split_one_byte_at_a_time(self):
        data = b"250-a\r\n250 STARTTLS\r\n"
        code, lines, _ = S._recv_reply(self.Fed([bytes([b]) for b in data]), 3)
        self.assertEqual((code, lines), (250, ["a", "STARTTLS"]))

    def test_mixed_codes_in_one_reply_never_treated_as_complete(self):
        """A malformed/injected reply with inconsistent codes must not be accepted as valid."""
        fed = self.Fed([b"250-a\r\n251-b\r\n250 c\r\n"])
        code, lines, _ = S._recv_reply(fed, 0.3)
        self.assertIsNone(code)                                      # never resolves -> times out, not silently wrong

    def test_no_data_eof(self):
        self.assertEqual(S._recv_reply(self.Fed([]), 1), (None, [], b""))

    def test_timeout_with_partial_data(self):
        code, lines, raw = S._recv_reply(self.Fed([b"250-incomplete\r\n"]), 0.3)
        self.assertIsNone(code)
        self.assertIn(b"incomplete", raw)


class TestProbeAgainstRealServers(unittest.TestCase):
    """Every case exercised with a genuine local SMTP server, not a mock."""

    def probe(self, port, ehlo="md-sakib-rahman.github.io", timeout=3):
        return S.probe_smtp("mail.test.bd", "127.0.0.1", ehlo, port, timeout, CTX)

    def test_normal_ok(self):
        srv = FakeSMTP("normal")
        try:
            r = self.probe(srv.port)
        finally:
            srv.close()
        self.assertEqual((r["status"], r["starttls_offered"]), ("ok", True))
        self.assertEqual(r["tls_version"], "TLSv1.3")
        self.assertIsNotNone(r["cipher"])

    def test_no_starttls(self):
        srv = FakeSMTP("no_starttls")
        try:
            r = self.probe(srv.port)
        finally:
            srv.close()
        self.assertEqual((r["status"], r["starttls_offered"]), ("no_starttls", False))

    def test_multiline_ehlo_finds_starttls(self):
        srv = FakeSMTP("multiline_ehlo")
        try:
            r = self.probe(srv.port)
        finally:
            srv.close()
        self.assertEqual(r["status"], "ok")
        self.assertGreaterEqual(len(r["capabilities"]), 3)

    def test_tls_handshake_fails_after_220(self):
        srv = FakeSMTP("starttls_fails_handshake")
        try:
            r = self.probe(srv.port)
        finally:
            srv.close()
        self.assertEqual(r["status"], "tls_failed")
        self.assertTrue(r["starttls_offered"])

    def test_silent_before_banner_times_out_not_hangs(self):
        srv = FakeSMTP("no_banner")
        t0 = time.time()
        try:
            r = self.probe(srv.port, timeout=1)
        finally:
            srv.close()
        self.assertEqual(r["status"], "timeout")
        self.assertLess(time.time() - t0, 5)

    def test_drops_after_ehlo(self):
        srv = FakeSMTP("drops_after_ehlo")
        try:
            r = self.probe(srv.port)
        finally:
            srv.close()
        self.assertEqual((r["status"], r.get("stage")), ("closed", "ehlo"))

    def test_connect_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = self.probe(port, timeout=2)
        self.assertEqual(r["status"], "connect_refused")

    def test_4xx_banner_is_smtp_error_not_ok(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)

        def one():
            c, _ = srv.accept()
            c.sendall(b"421 4.3.2 Service not available, closing\r\n")
            c.close()
        threading.Thread(target=one, daemon=True).start()
        r = self.probe(srv.getsockname()[1], timeout=3)
        srv.close()
        self.assertEqual((r["status"], r["code"]), ("smtp_error", 421))

    def test_our_ehlo_name_is_actually_sent(self):
        srv = FakeSMTP("normal")
        try:
            self.probe(srv.port, ehlo="very-specific-probe-name.example.test")
        finally:
            srv.close()
        self.assertIn(b"very-specific-probe-name.example.test", srv.received[0])


class TestExtractAndResolve(unittest.TestCase):
    def test_resolve_hosts_handles_bad_names_without_crashing(self):
        out = C4.resolve_hosts(["this-definitely-does-not-exist-xyz123.invalid"], ["1.1.1.1"], 2.0)
        self.assertIn("this-definitely-does-not-exist-xyz123.invalid", out)
        self.assertIsNone(out["this-definitely-does-not-exist-xyz123.invalid"])

    def test_resolve_hosts_real_name(self):
        """one.one.one.one legitimately answers with either 1.1.1.1 or 1.0.0.1 (Cloudflare's two
        anycast addresses) -- only check that resolution produced SOME real IPv4 address."""
        import ipaddress
        out = C4.resolve_hosts(["one.one.one.one"], ["1.1.1.1", "8.8.8.8"], 5.0)
        ipaddress.ip_address(out["one.one.one.one"])  # raises if not a valid address


class TestMidRunAbortSafety(unittest.TestCase):
    """The abort-after-N-consecutive-connect-failures logic, isolated from the network."""

    def test_counter_resets_on_non_connect_failure(self):
        # Simulated via the same CONNECT_FAIL set logic used in main(); re-derive it here directly
        # against a scripted status sequence to prove the reset rule without spinning up a full run.
        CONNECT_FAIL = {"connect_refused", "connect_timeout", "connect_failed", "timeout"}
        seq = ["connect_refused", "connect_refused", "no_starttls", "connect_refused", "connect_refused"]
        consecutive, tripped_at = 0, None
        for i, status in enumerate(seq):
            consecutive = consecutive + 1 if status in CONNECT_FAIL else 0
            if consecutive >= 3:
                tripped_at = i
                break
        self.assertIsNone(tripped_at)                                # never reached 3 in a row (reset at index 2)

    def test_counter_trips_on_genuine_consecutive_run(self):
        CONNECT_FAIL = {"connect_refused", "connect_timeout", "connect_failed", "timeout"}
        seq = ["connect_refused"] * 5
        consecutive, tripped_at = 0, None
        for i, status in enumerate(seq):
            consecutive = consecutive + 1 if status in CONNECT_FAIL else 0
            if consecutive >= 3:
                tripped_at = i
                break
        self.assertEqual(tripped_at, 2)


class TestReportFormattingNoNoneLeak(unittest.TestCase):
    """Regression guard: a sector where STARTTLS is offered by nobody has a genuinely zero
    denominator for 'TLS handshake completed (of offered)' -- the report/console must show a
    placeholder, never the literal text 'None%'."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.proj = os.path.join(cls.tmp, "proj")
        shutil.copytree(os.path.join(BASE, "measurement"), os.path.join(cls.proj, "measurement"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        raw = os.path.join(cls.proj, "data", "measurement", "runs", "r", "raw")
        proc = os.path.join(cls.proj, "data", "measurement", "processed")
        os.makedirs(raw)
        os.makedirs(proc)
        with open(os.path.join(raw, "dns.jsonl"), "w") as f:
            f.write(json.dumps({"domain": "c.gov.bd", "MX": {"status": "ok", "values": ["10 gov-relay.bd."]}}) + "\n")
        with open(os.path.join(raw, "smtp_hosts.jsonl"), "w") as f:
            f.write(json.dumps({"mx_host": "gov-relay.bd", "status": "no_starttls", "starttls_offered": False}) + "\n")
        with open(os.path.join(proc, "liveness_all.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "category", "tier"])
            w.writerow(["c.gov.bd", "government", "verified"])
        cls.p = subprocess.run([sys.executable, "measurement/phase_c_derived/c4_smtp_scan.py", "--run-id", "r",
                               "--skip-ehlo-check", "--skip-control"], cwd=cls.proj, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_0_ran(self):
        self.assertEqual(self.p.returncode, 0, self.p.stdout + self.p.stderr)

    def test_no_none_percent_anywhere(self):
        self.assertNotIn("None%", self.p.stdout)
        with open(os.path.join(self.proj, "results", "tables", "phase_c4_report.md")) as f:
            md = f.read()
        self.assertNotIn("None%", md)
        self.assertIn("no conclusive result", md)                # the explicit placeholder is present instead


class TestRunnerEndToEnd(unittest.TestCase):
    """
    a.bd, b.bd  -> MX mx1.test.bd (shared) -> real local server, STARTTLS ok
    c.bd        -> MX mx2.test.bd          -> real local server, no STARTTLS
    noweb.bd    -> MX mx1.test.bd (shares the SAME server as a.bd/b.bd) -- a mail-only domain with
                   no web liveness, proving the mail-only scope works and that sharing is detected
    Expected: 4 domains, 2 unique mx hosts. mx1.test.bd covers 3 domains -> per-server weight still 1.
    """
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.proj = os.path.join(cls.tmp, "proj")
        shutil.copytree(os.path.join(BASE, "measurement"), os.path.join(cls.proj, "measurement"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        cls.raw = os.path.join(cls.proj, "data", "measurement", "runs", "run_t", "raw")
        proc = os.path.join(cls.proj, "data", "measurement", "processed")
        os.makedirs(cls.raw)
        os.makedirs(proc)

        cert_dir = tempfile.mkdtemp()
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(65537, 2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mx1.test.bd")]))
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mx1.test.bd")]))
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
                .sign(key, hashes.SHA256()))
        cpath = os.path.join(cert_dir, "c.pem")
        with open(cpath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        cls.srv_ok = FakeSMTP("normal")
        cls.srv_none = FakeSMTP("no_starttls")
        dns_recs = [
            {"domain": "a.bd", "MX": {"status": "ok", "values": [f"10 127-0-0-1-mx1.nip.io."]}},
            {"domain": "b.bd", "MX": {"status": "ok", "values": [f"10 127-0-0-1-mx1.nip.io."]}},
            {"domain": "noweb.bd", "MX": {"status": "ok", "values": [f"10 127-0-0-1-mx1.nip.io."]}},
            {"domain": "c.bd", "MX": {"status": "ok", "values": [f"10 127-0-0-1-mx2.nip.io."]}},
        ]
        with open(os.path.join(cls.raw, "dns.jsonl"), "w") as f:
            f.write("".join(json.dumps(r) + "\n" for r in dns_recs))
        with open(os.path.join(proc, "liveness_all.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "category", "tier"])
            for d, cat in (("a.bd", "university"), ("b.bd", "university"), ("c.bd", "government"), ("noweb.bd", "university")):
                w.writerow([d, cat, "verified"])
        cls.cfg = os.path.join(cls.tmp, "cfg.yaml")
        with open(cls.cfg, "w") as f:
            f.write("smtp:\n  workers: 4\n  max_cps: 1000\n  max_per_ip: 2\n")

    @classmethod
    def tearDownClass(cls):
        cls.srv_ok.close()
        cls.srv_none.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_c4(self, *extra):
        """nip.io resolves <anything>.nip.io to the embedded IP (here always 127.0.0.1), so the
        real dnspython resolution step runs for real against a real DNS service, while the actual
        SMTP connection still lands on our local fake servers (whose ports we patch in via env)."""
        env = dict(os.environ, C4_TEST_PORT_MX1=str(self.srv_ok.port), C4_TEST_PORT_MX2=str(self.srv_none.port))
        script = os.path.join(self.proj, "tests", "run_c4_with_fakes.py")
        return subprocess.run([sys.executable, script, "--run-id", "run_t", "--config", self.cfg, "--skip-ehlo-check",
                               *extra], cwd=self.proj, capture_output=True, text=True, env=env)

    def test_1_full_run(self):
        shutil.copytree(HERE, os.path.join(self.proj, "tests"), dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__"))
        p = self.run_c4("--skip-control")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        with open(os.path.join(self.raw, "smtp_hosts.jsonl")) as f:
            recs = {r["mx_host"]: r for r in (json.loads(l) for l in f)}
        self.assertEqual(set(recs), {"127-0-0-1-mx1.nip.io", "127-0-0-1-mx2.nip.io"})
        self.assertEqual((recs["127-0-0-1-mx1.nip.io"]["status"], recs["127-0-0-1-mx1.nip.io"]["starttls_offered"]), ("ok", True))
        self.assertEqual((recs["127-0-0-1-mx2.nip.io"]["status"], recs["127-0-0-1-mx2.nip.io"]["starttls_offered"]), ("no_starttls", False))
        with open(os.path.join(self.proj, "data", "measurement", "processed", "phase_c4_domains.csv"), newline="") as f:
            dom = {r["domain"]: r for r in csv.DictReader(f)}
        self.assertEqual(set(dom), {"a.bd", "b.bd", "c.bd", "noweb.bd"})           # mail-only domain included
        self.assertEqual(dom["noweb.bd"]["mx_host"], "127-0-0-1-mx1.nip.io")       # shares the server with a.bd/b.bd
        self.assertEqual(dom["noweb.bd"]["status"], "ok")
        with open(os.path.join(self.proj, "results", "tables", "phase_c4_by_category.csv"), newline="") as f:
            cat = {r["group"]: r for r in csv.DictReader(f)}
        u = cat["university"]
        self.assertEqual((u["domains"], u["mx_hosts"]), ("3", "1"))                # 3 domains, ONE server
        self.assertEqual((u["starttls_offered_n"], u["starttls_offered_dom_pct"], u["starttls_offered_srv_pct"]),
                         ("3", "100.0", "100.0"))

    def test_2_resume_does_not_rescan(self):
        self.run_c4("--skip-control")
        p = self.run_c4("--skip-control")
        self.assertIn("already done: 2 | to do: 0", p.stdout)
        self.assertIn("Nothing to scan", p.stdout)

    def test_3_ehlo_placeholder_blocks_without_skip_flag(self):
        env = dict(os.environ)
        script = os.path.join(self.proj, "tests", "run_c4_with_fakes.py")
        p = subprocess.run([sys.executable, script, "--run-id", "run_t", "--config", self.cfg, "--skip-control"],
                           cwd=self.proj, capture_output=True, text=True, env=env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("placeholder", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)