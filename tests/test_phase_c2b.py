#!/usr/bin/env python3
"""
Tests for Phase C2b (legacy SSLv3 / 3DES probes). Run from project root:  python tests/test_phase_c2b.py

Three layers:
  1. Parser tests on REAL captured `openssl s_client` output (tests/legacy_fixtures.py) -- always run.
  2. Scheduling/circuit-breaker tests with injected fake probes -- always run.
  3. Live tests against real local `openssl s_server` processes -- need the legacy OpenSSL build
     (bash tools/build_legacy_openssl.sh, or set LEGACY_OPENSSL=/path/to/openssl). They are SKIPPED,
     loudly, if it is missing.
"""
import csv
import json
import os
import shutil
import signal
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

from legacy_fixtures import FIXTURES as FX
from measurement.phase_c_derived import c2b_legacy_scan as C2B
from measurement.phase_c_derived import legacy_probe as L
from measurement.phase_c_derived.c2_legacy_cipher_inference import is_cbc_mode

BIN = os.environ.get("LEGACY_OPENSSL") or os.path.join(BASE, "tools", "legacy_openssl", "bin", "openssl")
HAVE_BIN = os.path.isfile(BIN) and os.access(BIN, os.X_OK)
NEED_BIN = unittest.skipUnless(HAVE_BIN, f"legacy OpenSSL not built at {BIN}: run  bash tools/build_legacy_openssl.sh")


# ------------------------------------------------------------------ 1. parser on real output

class TestParserOnRealOutput(unittest.TestCase):
    def test_sslv3_accepted(self):
        r = L.parse_s_client(FX["ssl3_ok"])
        self.assertEqual((r["status"], r["protocol"], r["cipher"]), ("accepted", "SSLv3", "DHE-RSA-AES256-SHA"))

    def test_3des_accepted_and_protocol_is_from_session_block_not_the_New_line(self):
        """The real output contains 'New, SSLv3, Cipher is DES-CBC3-SHA' although the connection was
        TLS 1.2. The parser must report the negotiated protocol, not the cipher's introduction version."""
        self.assertIn("New, SSLv3, Cipher is DES-CBC3-SHA", FX["des3_ok"])
        r = L.parse_s_client(FX["des3_ok"])
        self.assertEqual((r["status"], r["protocol"], r["cipher"]), ("accepted", "TLSv1.2", "DES-CBC3-SHA"))

    def test_failed_handshake_still_prints_protocol_and_0000_but_is_not_accepted(self):
        for name in ("ssl3_alert", "des3_alert"):
            self.assertIn("Cipher    : 0000", FX[name])
            self.assertIn("Protocol  :", FX[name])
            r = L.parse_s_client(FX[name])
            self.assertEqual(r["status"], "refused", name)
            self.assertIn("alert 40", r["detail"])
            self.assertNotIn("cipher", r)

    def test_connect_failed(self):
        r = L.parse_s_client(FX["conn_refused"])
        self.assertEqual((r["status"], r["detail"]), ("connect_failed", "errno=111"))

    def test_server_closes_without_answer(self):
        self.assertEqual(L.parse_s_client(FX["closed_eof"])["status"], "closed")

    def test_not_tls_server(self):
        r = L.parse_s_client(FX["not_tls"])
        self.assertEqual(r["status"], "refused")
        self.assertIn("wrong version number", r["detail"])

    def test_empty_output(self):
        self.assertEqual(L.parse_s_client("")["status"], "connect_failed")

    def test_tri_state(self):
        self.assertEqual([L.tri_state(s) for s in ("accepted", "refused", "closed", "timeout", "connect_failed", "error")],
                         [True, False, False, None, None, None])

    def test_targets(self):
        self.assertEqual((L.target_for("1.2.3.4", 443), L.target_for("2001:db8::1", 443)), ("1.2.3.4:443", "[2001:db8::1]:443"))

    def test_hostile_or_bad_input_never_reaches_a_subprocess(self):
        def boom(*a, **k):
            raise AssertionError("subprocess must not be started")
        orig = L.subprocess.run
        L.subprocess.run = boom
        try:
            for host in ("bad host;rm -rf /", "-servername", "a b.bd", "", None):
                self.assertEqual(L.probe_3des("x", host, "1.2.3.4")["status"], "error", host)
            self.assertEqual(L.probe_3des("x", "a.bd", "not-an-ip")["status"], "error")
            self.assertIsNone(L.probe_sslv3("x", "not-an-ip")["accepts_sslv3"])
        finally:
            L.subprocess.run = orig


# ------------------------------------------------------------------ 2. scheduling with fake probes

class Fake:
    def __init__(self, sslv3=None, des=None, tcp=True):
        self.sslv3 = sslv3 or {"accepts_sslv3": False, "poodle_exposed": False, "offer_all": {"status": "refused"}}
        self.des, self.tcp = des or {}, tcp
        self.calls, self.sleeps, self.w_ssl, self.w_des = [], [], [], []

    def probe_sslv3(self, openssl, ip, port, timeout, pace=None):
        self.calls.append(("sslv3", ip))
        return dict(self.sslv3)

    def probe_3des(self, openssl, host, ip, port, timeout, pace=None):
        self.calls.append(("3des", host))
        return dict(self.des.get(host, {"status": "refused", "accepts_3des": False}))

    def tcp_ok(self, ip, port):
        return self.tcp(ip) if callable(self.tcp) else self.tcp

    def run(self, domains, need_sslv3=True, breaker_after=3, interval=1.5, should_stop=None):
        return C2B.process_ip("9.9.9.9", domains, need_sslv3, openssl="x", port=443, timeout=1, interval=interval,
                              breaker_after=breaker_after, pace=None, write_sslv3=self.w_ssl.append,
                              write_des3=self.w_des.append, probe_sslv3=self.probe_sslv3, probe_3des=self.probe_3des,
                              tcp_ok=self.tcp_ok, sleep=self.sleeps.append, should_stop=should_stop or (lambda: False))


TIMEOUT = {"status": "timeout", "accepts_3des": None}


class TestProcessIp(unittest.TestCase):
    def test_sslv3_once_then_each_domain_in_order_with_spacing(self):
        f = Fake()
        res = f.run(["a.bd", "b.bd", "c.bd"])
        self.assertEqual(f.calls, [("sslv3", "9.9.9.9"), ("3des", "a.bd"), ("3des", "b.bd"), ("3des", "c.bd")])
        self.assertEqual(len(f.w_ssl), 1)
        self.assertEqual([r["domain"] for r in f.w_des], ["a.bd", "b.bd", "c.bd"])
        self.assertEqual(f.sleeps, [1.5, 1.5, 1.5])            # 4 connections -> 3 gaps, none before the first
        self.assertEqual((res["tripped"], res["deferred"]), (False, []))

    def test_already_done_sslv3_is_not_repeated(self):
        f = Fake()
        f.run(["a.bd"], need_sslv3=False)
        self.assertEqual(f.calls, [("3des", "a.bd")])
        self.assertEqual(f.sleeps, [])

    def test_breaker_trips_after_n_consecutive_unreachable_and_defers_the_rest(self):
        f = Fake(des={f"d{i}.bd": TIMEOUT for i in range(10)}, tcp=lambda ip: False)
        f.sslv3 = {"accepts_sslv3": False, "poodle_exposed": False, "offer_all": {"status": "refused"}}
        res = f.run([f"d{i}.bd" for i in range(10)], breaker_after=3)
        self.assertTrue(res["tripped"])
        self.assertEqual(len([c for c in f.calls if c[0] == "3des"]), 3)      # stopped hammering after 3
        self.assertEqual(res["deferred"], [f"d{i}.bd" for i in range(10)])    # 3 tried + 7 never tried
        self.assertEqual(f.w_des, [])                                         # nothing written: a re-run retries them

    def test_consecutive_counter_resets_on_a_usable_answer(self):
        des = {"a.bd": TIMEOUT, "b.bd": TIMEOUT, "c.bd": {"status": "refused", "accepts_3des": False},
               "d.bd": TIMEOUT, "e.bd": TIMEOUT}
        f = Fake(des=des, tcp=lambda ip: False)
        res = f.run(["a.bd", "b.bd", "c.bd", "d.bd", "e.bd"], breaker_after=3)
        self.assertFalse(res["tripped"])
        self.assertEqual(res["deferred"], ["a.bd", "b.bd", "d.bd", "e.bd"])
        self.assertEqual([r["domain"] for r in f.w_des], ["c.bd"])

    def test_protocol_specific_silence_is_recorded_not_deferred_and_never_trips(self):
        """TCP connects but the legacy hello gets no answer: that is the server's behaviour, an observation."""
        f = Fake(des={f"d{i}.bd": TIMEOUT for i in range(6)}, tcp=True)
        res = f.run([f"d{i}.bd" for i in range(6)], breaker_after=2)
        self.assertEqual((res["tripped"], res["deferred"]), (False, []))
        self.assertEqual(len(f.w_des), 6)
        self.assertTrue(all(r["accepts_3des"] is None for r in f.w_des))

    def test_unreachable_ip_at_sslv3_stage_defers_everything_and_writes_nothing(self):
        f = Fake(sslv3={"accepts_sslv3": None, "poodle_exposed": None, "offer_all": {"status": "timeout"}}, tcp=False)
        res = f.run(["a.bd", "b.bd"])
        self.assertTrue(res["tripped"] and res["sslv3_deferred"])
        self.assertEqual((f.w_ssl, f.w_des, res["deferred"]), ([], [], ["a.bd", "b.bd"]))
        self.assertEqual([c for c in f.calls if c[0] == "3des"], [])

    def test_stop_flag_halts_between_probes_and_does_not_defer_untried_domains(self):
        f = Fake()
        res = f.run(["a.bd", "b.bd", "c.bd", "d.bd"], should_stop=lambda: len(f.calls) >= 3)
        self.assertEqual(f.calls, [("sslv3", "9.9.9.9"), ("3des", "a.bd"), ("3des", "b.bd")])
        self.assertTrue(res["stopped"])
        self.assertEqual((res["tripped"], res["deferred"]), (False, []))     # untried = still pending, not deferred
        self.assertEqual([r["domain"] for r in f.w_des], ["a.bd", "b.bd"])

    def test_stop_before_the_first_probe_writes_nothing(self):
        f = Fake()
        res = f.run(["a.bd"], should_stop=lambda: True)
        self.assertEqual((f.calls, f.w_ssl, f.w_des), ([], [], []))
        self.assertTrue(res["stopped"])

    def test_inconclusive_sslv3_on_a_reachable_ip_is_recorded_and_scan_continues(self):
        f = Fake(sslv3={"accepts_sslv3": None, "poodle_exposed": None, "offer_all": {"status": "timeout"}}, tcp=True)
        res = f.run(["a.bd"])
        self.assertEqual(len(f.w_ssl), 1)
        self.assertIsNone(f.w_ssl[0]["accepts_sslv3"])
        self.assertEqual(len(f.w_des), 1)
        self.assertFalse(res["tripped"])


# ------------------------------------------------------------------ 3. live tests with a real legacy OpenSSL

@NEED_BIN
class TestLiveProbes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cert, cls.key = L.make_test_cert(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def server(self, *args):
        return L.local_server(BIN, self.cert, self.key, list(args))

    def test_capabilities_and_self_test(self):
        self.assertIn("1.1.1", L.check_capabilities(BIN))
        results = L.self_test(BIN)
        self.assertEqual(set(results), {"sslv3_on_legacy", "sslv3_on_modern", "3des_on_3des", "3des_on_modern"})

    def test_wrong_binary_is_refused_not_silently_used(self):
        with self.assertRaises(RuntimeError):
            L.check_capabilities(os.path.join(self.tmp, "does-not-exist"))
        system = shutil.which("openssl")
        if system and os.path.realpath(system) != os.path.realpath(BIN):
            out = subprocess.run([system, "s_client", "-help"], capture_output=True, text=True)
            if "-ssl3" not in out.stdout + out.stderr:                       # a normal modern system OpenSSL
                with self.assertRaises(RuntimeError):
                    L.check_capabilities(system)

    def test_sslv3_accepted_with_cbc_is_poodle_exposed(self):
        with self.server("-ssl3", "-cipher", "ALL:@SECLEVEL=0") as port:
            r = L.probe_sslv3(BIN, "127.0.0.1", port, 8)
        self.assertEqual((r["accepts_sslv3"], r["poodle_exposed"], r["offer_cbc"]), (True, True, None))
        self.assertTrue(is_cbc_mode(r["offer_all"]["cipher"]))

    def test_rc4_preferring_server_with_cbc_enabled_is_found_by_the_second_probe(self):
        with self.server("-ssl3", "-serverpref", "-cipher", "RC4-SHA:AES128-SHA:@SECLEVEL=0") as port:
            r = L.probe_sslv3(BIN, "127.0.0.1", port, 8)
        self.assertEqual(r["offer_all"]["cipher"], "RC4-SHA")                # first probe alone would say "harmless"
        self.assertEqual((r["accepts_sslv3"], r["poodle_exposed"]), (True, True))
        self.assertEqual(r["offer_cbc"]["cipher"], "AES128-SHA")

    def test_rc4_only_sslv3_server_accepts_sslv3_but_is_not_poodle_exposed(self):
        with self.server("-ssl3", "-cipher", "RC4-SHA:@SECLEVEL=0") as port:
            r = L.probe_sslv3(BIN, "127.0.0.1", port, 8)
        self.assertEqual((r["accepts_sslv3"], r["poodle_exposed"], r["offer_cbc"]["status"]), (True, False, "refused"))

    def test_modern_server_refuses_sslv3(self):
        with self.server("-no_ssl3", "-no_tls1", "-no_tls1_1", "-cipher", "HIGH:!3DES") as port:
            r = L.probe_sslv3(BIN, "127.0.0.1", port, 8)
        self.assertEqual((r["accepts_sslv3"], r["poodle_exposed"], r["offer_all"]["status"]), (False, False, "refused"))

    def test_cbc_only_offer_really_contains_only_cbc_suites(self):
        out = subprocess.run([BIN, "ciphers", "-v", L.SSLV3_CBC_ONLY], capture_output=True, text=True).stdout
        names = [ln.split()[0] for ln in out.splitlines() if len(ln.split()) > 1 and ln.split()[1] == "SSLv3"]
        self.assertGreater(len(names), 20)
        self.assertEqual([n for n in names if not is_cbc_mode(n)], [])
        self.assertFalse([n for n in names if "RC4" in n or "NULL" in n])

    def test_3des_accepted_on_tls10_and_tls12(self):
        for flag, proto in (("-tls1", "TLSv1"), ("-tls1_2", "TLSv1.2")):
            with self.server(flag, "-cipher", "DES-CBC3-SHA:@SECLEVEL=0") as port:
                r = L.probe_3des(BIN, "t.bd", "127.0.0.1", port, 8)
            self.assertEqual((r["accepts_3des"], r["protocol"], r["cipher"]), (True, proto, "DES-CBC3-SHA"))

    def test_3des_refused_by_modern_server(self):
        with self.server("-no_ssl3", "-no_tls1", "-no_tls1_1", "-cipher", "HIGH:!3DES") as port:
            r = L.probe_3des(BIN, "t.bd", "127.0.0.1", port, 8)
        self.assertEqual((r["accepts_3des"], r["status"]), (False, "refused"))

    def test_hostname_is_in_the_3des_hello_and_absent_from_the_sslv3_hello(self):
        """Capture the raw ClientHello bytes each probe actually sends. SNI travels in clear text in
        TLS 1.0-1.2, so the 3DES hello must contain the domain; SSLv3 has no extensions, so its hello
        cannot (and must not) -- which is why SSLv3 is probed once per IP."""
        name = b"very-specific-name.example.ac.bd"
        captured = []
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)

        def loop():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                c.settimeout(3)
                try:
                    captured.append(c.recv(4096))
                except OSError:
                    captured.append(b"")
                c.close()
        threading.Thread(target=loop, daemon=True).start()
        port = srv.getsockname()[1]
        L.probe_3des(BIN, name.decode(), "127.0.0.1", port, 4)
        L.probe_sslv3(BIN, "127.0.0.1", port, 4)
        srv.close()
        self.assertEqual(len(captured), 2, captured)
        des_hello, ssl3_hello = captured
        self.assertIn(name, des_hello)                                # SNI present (TLS 1.0-1.2)
        self.assertNotIn(name, ssl3_hello)                            # nothing to carry it in SSLv3
        self.assertEqual(ssl3_hello[:1], b"\x16")                     # both really are TLS handshake records
        self.assertEqual(des_hello[:1], b"\x16")

    def test_failure_shapes(self):
        closed = L.free_port()
        self.assertEqual(L.probe_3des(BIN, "t.bd", "127.0.0.1", closed, 4)["status"], "connect_failed")
        self.assertIsNone(L.probe_3des(BIN, "t.bd", "127.0.0.1", closed, 4)["accepts_3des"])

        def serve(mode):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            s.listen(5)

            def loop():
                while True:
                    try:
                        c, _ = s.accept()
                    except OSError:
                        return
                    if mode == "close":
                        c.close()
                    elif mode == "http":
                        c.recv(100)
                        c.sendall(b"HTTP/1.1 400 Bad\r\n\r\nplain")
                        c.close()
            threading.Thread(target=loop, daemon=True).start()
            return s

        for mode, expect_status, expect_flag in (("close", "closed", False), ("http", "refused", False)):
            s = serve(mode)
            r = L.probe_3des(BIN, "t.bd", "127.0.0.1", s.getsockname()[1], 4)
            s.close()
            self.assertEqual((r["status"], r["accepts_3des"]), (expect_status, expect_flag), mode)
        hold = socket.socket()
        hold.bind(("127.0.0.1", 0))
        hold.listen(5)                                                        # accepts TCP, never answers
        t0 = time.time()
        r = L.probe_3des(BIN, "t.bd", "127.0.0.1", hold.getsockname()[1], 2)
        hold.close()
        self.assertEqual((r["status"], r["accepts_3des"]), ("timeout", None))
        self.assertLess(time.time() - t0, 6)


@NEED_BIN
class TestRunnerEndToEnd(unittest.TestCase):
    """
    127.0.0.1 : a1.bd, a2.bd  -> server accepting SSLv3 and 3DES (SSLv3 probed ONCE, 3DES per domain)
    127.0.0.2 : b1.bd         -> modern server, refuses both
    127.0.0.3 : c1..c3.bd     -> nothing listening: unreachable -> circuit breaker (breaker_after=2), all deferred
    """
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.proj = os.path.join(cls.tmp, "proj")
        shutil.copytree(os.path.join(BASE, "measurement"), os.path.join(cls.proj, "measurement"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(HERE, os.path.join(cls.proj, "tests"), ignore=shutil.ignore_patterns("__pycache__"))
        cls.raw = os.path.join(cls.proj, "data", "measurement", "runs", "run_t", "raw")
        proc = os.path.join(cls.proj, "data", "measurement", "processed")
        os.makedirs(cls.raw)
        os.makedirs(proc)
        cls.live = [("a1.bd", "127.0.0.1"), ("a2.bd", "127.0.0.1"), ("b1.bd", "127.0.0.2"),
                    ("c1.bd", "127.0.0.3"), ("c2.bd", "127.0.0.3"), ("c3.bd", "127.0.0.3")]
        with open(os.path.join(cls.raw, "port443.jsonl"), "w") as f:
            f.write("".join(json.dumps({"domain": d, "port443": "open"}) + "\n" for d, _ in cls.live))
        with open(os.path.join(proc, "live_domains.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "sector", "category", "tier", "ip", "family"])
            for d, ip in cls.live:
                w.writerow([d, "x", "x", "verified", ip, "4"])
        cert, key = L.make_test_cert(cls.tmp)
        port = L.free_port()
        cls.port = port
        cls.s1 = L.local_server(BIN, cert, key, ["-cipher", "ALL:@SECLEVEL=0"], host="127.0.0.1", port=port)
        cls.s2 = L.local_server(BIN, cert, key, ["-no_ssl3", "-no_tls1", "-no_tls1_1", "-cipher", "HIGH:!3DES"],
                                host="127.0.0.2", port=port)
        cls.s1.__enter__()
        cls.s2.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.s1.__exit__(None, None, None)
        cls.s2.__exit__(None, None, None)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_c2b(self, *extra):
        cfg = os.path.join(self.tmp, "cfg.yaml")
        with open(cfg, "w") as f:
            f.write("legacy:\n  breaker_after: 2\n  workers: 4\n  max_cps: 1000\n")
        return subprocess.run([sys.executable, "tests/run_c2b_with_fakes.py", str(self.port), "--run-id", "run_t",
                               "--openssl", BIN, "--config", cfg, "--per-ip-interval-s", "0", "--timeout-s", "5", *extra],
                              cwd=self.proj, capture_output=True, text=True)

    def load(self, name):
        with open(os.path.join(self.raw, name)) as f:
            return [json.loads(l) for l in f]

    def test_1_full_run(self):
        p = self.run_c2b()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("Control check passed", p.stdout)
        ssl = {r["ip"]: r for r in self.load("legacy_sslv3_ip.jsonl")}
        self.assertEqual(set(ssl), {"127.0.0.1", "127.0.0.2"})                   # once per IP; unreachable IP deferred
        self.assertEqual((ssl["127.0.0.1"]["accepts_sslv3"], ssl["127.0.0.1"]["poodle_exposed"]), (True, True))
        self.assertEqual((ssl["127.0.0.2"]["accepts_sslv3"], ssl["127.0.0.2"]["poodle_exposed"]), (False, False))
        des = {r["domain"]: r for r in self.load("legacy_3des.jsonl")}
        self.assertEqual(set(des), {"a1.bd", "a2.bd", "b1.bd"})                  # c* never written
        self.assertTrue(des["a1.bd"]["accepts_3des"] and des["a2.bd"]["accepts_3des"])
        self.assertIn("DES-CBC3", des["a1.bd"]["cipher"])
        self.assertIn(des["a1.bd"]["protocol"], ("TLSv1", "TLSv1.1", "TLSv1.2"))
        self.assertFalse(des["b1.bd"]["accepts_3des"])
        self.assertIn("DEFERRED: 3 domains on 1 unreachable IPs", p.stdout)
        with open(os.path.join(self.proj, "data", "measurement", "runs", "run_t", "run_meta.json")) as f:
            meta = json.load(f)["legacy"]
        self.assertEqual((meta["tripped_ips"], meta["deferred_domains"]), (["127.0.0.3"], 3))
        self.assertEqual(len(meta["openssl_sha256"]), 64)
        self.assertIn("1.1.1", meta["openssl"])
        self.assertEqual(meta["cipher_strings"]["3des"], L.DES3)

    def test_2_resume_only_retries_what_was_deferred(self):
        self.run_c2b()
        p = self.run_c2b("--skip-control")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("IPs still needing SSLv3: 1 | domains still needing 3DES: 3", p.stdout)
        self.assertEqual(len(self.load("legacy_3des.jsonl")), 3)                # nothing duplicated
        self.assertEqual(len(self.load("legacy_sslv3_ip.jsonl")), 2)

    def test_4_c2_reads_the_real_c2b_output(self):
        """Schema contract: c2b's actual output files feed c2 without any adaptation."""
        self.run_c2b()
        proc = os.path.join(self.proj, "data", "measurement", "processed")
        with open(os.path.join(proc, "phase_b_domains.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "category", "tier", "ip", "is_service_hostname"])
            for d, ip in self.live:
                w.writerow([d, "university", "verified", ip, "False"])
        with open(os.path.join(self.raw, "tls.jsonl"), "w") as f:
            for d, _ in self.live:
                f.write(json.dumps({"domain": d, "cipher": "X25519MLKEM768", "tls_version": "TLSv1.3",
                                    "probes": {"old_versions": {"status": "tls_alert"}}}) + "\n")
        p = subprocess.run([sys.executable, "measurement/phase_c_derived/c2_legacy_cipher_inference.py",
                            "--run-id", "run_t"], cwd=self.proj, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        with open(os.path.join(proc, "phase_c2_ciphers.csv"), newline="") as f:
            rows = {r["domain"]: r for r in csv.DictReader(f)}
        self.assertEqual((rows["a1.bd"]["accepts_sslv3"], rows["a1.bd"]["poodle_exposed"], rows["a2.bd"]["accepts_sslv3"]),
                         ("True", "True", "True"))                       # one IP record covers both domains
        self.assertEqual((rows["a1.bd"]["accepts_3des"], rows["a1.bd"]["des3_protocol"]), ("True", rows["a1.bd"]["des3_protocol"]))
        self.assertIn("DES-CBC3", rows["a1.bd"]["des3_cipher"])
        self.assertEqual((rows["b1.bd"]["accepts_sslv3"], rows["b1.bd"]["accepts_3des"]), ("False", "False"))
        self.assertEqual((rows["c1.bd"]["accepts_sslv3"], rows["c1.bd"]["accepts_3des"]), ("", ""))   # deferred -> unknown
        with open(os.path.join(self.proj, "results", "tables", "phase_c2_by_category.csv"), newline="") as f:
            allrow = [r for r in csv.DictReader(f) if r["group"] == "ALL"][0]
        self.assertEqual((allrow["accepts_sslv3_n"], allrow["accepts_sslv3_den"]), ("2", "3"))         # a1,a2 yes; b1 no; c* excluded
        self.assertEqual((allrow["poodle_exposed_n"], allrow["accepts_3des_n"], allrow["accepts_3des_den"]), ("2", "2", "3"))

    def test_6_ctrl_c_stops_promptly_and_the_resume_completes_without_duplicates(self):
        """Sends a real SIGINT to a running scan (3 s between connections, so it is mid-wait)."""
        rid = "run_sig"
        raw = os.path.join(self.proj, "data", "measurement", "runs", rid, "raw")
        os.makedirs(raw)
        shutil.copy(os.path.join(self.raw, "port443.jsonl"), raw)
        cfg = os.path.join(self.tmp, "cfg_sig.yaml")
        with open(cfg, "w") as f:
            f.write("legacy:\n  breaker_after: 2\n  workers: 4\n  max_cps: 1000\n  heartbeat_s: 1\n")

        def cmd(interval):
            return [sys.executable, "tests/run_c2b_with_fakes.py", str(self.port), "--run-id", rid, "--openssl", BIN,
                    "--config", cfg, "--per-ip-interval-s", str(interval), "--timeout-s", "5"]
        p = subprocess.Popen(cmd(3), cwd=self.proj, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ssl_path = os.path.join(raw, "legacy_sslv3_ip.jsonl")
        for _ in range(150):                                            # wait until it is demonstrably mid-run
            if os.path.exists(ssl_path) and os.path.getsize(ssl_path) > 0:
                break
            time.sleep(0.1)
        t0 = time.time()
        p.send_signal(signal.SIGINT)
        out = p.communicate(timeout=40)[0]
        self.assertLess(time.time() - t0, 15, out)
        self.assertEqual(p.returncode, 1, out)
        self.assertIn("Progress is saved", out)
        self.assertIn("Interrupted -- progress is saved; re-run the same command to resume.", out)
        self.assertNotIn("Traceback", out)
        for name in ("legacy_sslv3_ip.jsonl", "legacy_3des.jsonl"):
            path = os.path.join(raw, name)
            if os.path.exists(path):
                with open(path) as f:
                    for line in f:
                        json.loads(line)                                # every line on disk is a complete record
        p2 = subprocess.run(cmd(0), cwd=self.proj, capture_output=True, text=True)
        self.assertEqual(p2.returncode, 0, p2.stdout + p2.stderr)
        with open(os.path.join(raw, "legacy_3des.jsonl")) as f:
            domains = [json.loads(l)["domain"] for l in f]
        with open(ssl_path) as f:
            ips = [json.loads(l)["ip"] for l in f]
        self.assertEqual(sorted(domains), ["a1.bd", "a2.bd", "b1.bd"])   # each exactly once
        self.assertEqual(sorted(ips), ["127.0.0.1", "127.0.0.2"])

    def test_7_heartbeat_progress_is_printed(self):
        rid = "run_hb"
        raw = os.path.join(self.proj, "data", "measurement", "runs", rid, "raw")
        os.makedirs(raw)
        shutil.copy(os.path.join(self.raw, "port443.jsonl"), raw)
        cfg = os.path.join(self.tmp, "cfg_hb.yaml")
        with open(cfg, "w") as f:
            f.write("legacy:\n  breaker_after: 2\n  workers: 4\n  max_cps: 1000\n  heartbeat_s: 1\n")
        p = subprocess.run([sys.executable, "tests/run_c2b_with_fakes.py", str(self.port), "--run-id", rid, "--openssl", BIN,
                            "--config", cfg, "--per-ip-interval-s", "1.2", "--timeout-s", "5", "--skip-control"],
                           cwd=self.proj, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertRegex(p.stdout, r"\[0m0\ds\] IPs finished \d+/3 \| 3DES domains \d+/6")
        self.assertIn("Largest IP has 3 domains", p.stdout)

    def test_5_missing_binary_aborts_with_build_instructions(self):
        cmd = [sys.executable, "tests/run_c2b_with_fakes.py", str(self.port), "--run-id", "run_t", "--openssl",
               os.path.join(self.tmp, "nope")]
        p = subprocess.run(cmd, cwd=self.proj, capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("build_legacy_openssl.sh", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)