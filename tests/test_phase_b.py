#!/usr/bin/env python3
"""
Tests for Phase B (b1 TLS scan). Real TLS handshakes against local servers on 127.0.0.1 --
no internet needed. Run from project root:  python tests/test_phase_b.py
"""

import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)
sys.path.insert(0, HERE)

from OpenSSL import SSL

import tls_fakes as F
from measurement.phase_b_tls import tls_probe as T

TMP = tempfile.mkdtemp()
CA_KEY, CA = F.make_ca()
CA_PEM = os.path.join(TMP, "ca.pem")
F.write_pem(CA_PEM, [CA])
STORE = T.load_trust_store(CA_PEM)
CTXS = T.build_contexts()
H = "test.bd"
LEAF_KEY, LEAF = F.make_leaf(CA_KEY, CA, [H, "other.bd"])


def scan(port, host=H, timeout=3.0, gate=None):
    return T.scan_domain(host, "127.0.0.1", CTXS, STORE, port=port, timeout=timeout, gate=gate)


class Srv:
    """with Srv(...) as s: -> a TLSServer that is closed afterwards"""
    def __init__(self, key=LEAF_KEY, cert=LEAF, **kw):
        self.s = F.TLSServer(key, cert, **kw)

    def __enter__(self):
        return self.s

    def __exit__(self, *a):
        self.s.close()


class TestLibrary(unittest.TestCase):
    def test_selftest_and_six_pq_groups(self):
        v = T.selftest()
        self.assertIn("X25519MLKEM768", v["pqc_groups_offered"])
        self.assertEqual(len(T.supported_pqc_groups()), len(T.PQC_CANDIDATES))
        self.assertEqual(CTXS["_groups"]["default"], T.DEFAULT_GROUPS)

    def test_is_pq_group(self):
        for g, exp in [("X25519MLKEM768", True), ("SecP256r1MLKEM768", True), ("MLKEM512", True),
                       ("x25519", False), ("secp256r1", False), (None, False)]:
            self.assertEqual(T.is_pq_group(g), exp, g)

    def test_hostname_matching(self):
        m = T.hostname_matches
        self.assertTrue(m("a.gov.bd", ["a.gov.bd"]))
        self.assertTrue(m("A.GOV.BD.", ["a.gov.bd"]))
        self.assertTrue(m("x.a.gov.bd", ["*.a.gov.bd"]))
        self.assertFalse(m("y.x.a.gov.bd", ["*.a.gov.bd"]))          # wildcard covers one label only
        self.assertFalse(m("a.gov.bd", ["*.a.gov.bd"]))
        self.assertFalse(m("b.gov.bd", ["a.gov.bd"]))


class TestPQClassification(unittest.TestCase):
    """Each server type from the design discussion, handshaked for real."""

    def test_pq_default(self):
        with Srv() as s:
            r = scan(s.port)
        self.assertEqual((r["status"], r["tls_version"], r["pq_class"]), ("ok", "TLSv1.3", "pq_default"))
        self.assertEqual(r["group"], "X25519MLKEM768")
        self.assertEqual(r["probes"]["pqc_only"], {"status": "skipped", "reason": "already_pq"})
        self.assertNotIn("classical", r["probes"])
        self.assertFalse(r["accepts_tls_1_0_or_1_1"])                  # modern-only server: TLS1.0/1.1 refused

    def test_capable_but_prefers_classical(self):
        with Srv(groups="X25519:X25519MLKEM768", server_pref=True) as s:
            r = scan(s.port)
        self.assertEqual((r["group"], r["pq_class"]), ("x25519", "pq_capable_not_default"))
        self.assertEqual(r["probes"]["pqc_only"]["group"], "X25519MLKEM768")

    def test_capable_only_via_secp256r1_hybrid(self):
        with Srv(groups="secp256r1:SecP256r1MLKEM768", server_pref=True) as s:
            r = scan(s.port)
        self.assertEqual((r["group"], r["pq_class"]), ("secp256r1", "pq_capable_not_default"))
        self.assertEqual(r["probes"]["pqc_only"]["group"], "SecP256r1MLKEM768")

    def test_capable_only_via_pure_mlkem(self):
        with Srv(groups="X25519:MLKEM768", server_pref=True) as s:
            r = scan(s.port)
        self.assertEqual(r["pq_class"], "pq_capable_not_default")
        self.assertEqual(r["probes"]["pqc_only"]["group"], "MLKEM768")

    def test_not_capable(self):
        with Srv(groups="X25519:secp256r1") as s:
            r = scan(s.port)
        self.assertEqual((r["group"], r["pq_class"]), ("x25519", "not_capable"))
        self.assertEqual(r["probes"]["pqc_only"]["status"], "tls_alert")

    def test_tls12_only(self):
        with Srv(max_v=SSL.TLS1_2_VERSION) as s:
            r = scan(s.port)
        self.assertEqual((r["tls_version"], r["pq_class"]), ("TLSv1.2", "no_tls13"))
        self.assertEqual(r["probes"]["pqc_only"], {"status": "skipped", "reason": "not_tls13"})

    def test_tls10_only_reached_by_legacy_probe(self):
        with Srv(min_v=SSL.TLS1_VERSION, max_v=SSL.TLS1_VERSION, seclevel0=True) as s:
            r = scan(s.port)
        self.assertEqual((r["status"], r["primary_probe"], r["tls_version"]), ("ok", "legacy", "TLSv1"))
        self.assertTrue(r["legacy_only"])
        self.assertEqual(r["pq_class"], "no_tls13")
        self.assertIsNotNone(r["cert"])                               # certificate still captured
        self.assertEqual(r["probes"]["default"]["status"], "tls_alert")

    def test_pq_intolerant_middlebox(self):
        with Srv(groups="X25519:secp256r1") as backend:
            mb = F.DropLargeClientHello(backend.port, limit=1000)
            try:
                r = scan(mb.port, timeout=2.0)
            finally:
                mb.close()
        self.assertEqual(r["probes"]["default"]["status"], "timeout")
        self.assertEqual((r["status"], r["primary_probe"], r["pq_intolerant"]), ("ok", "classical", True))
        self.assertEqual(r["tls_version"], "TLSv1.3")
        self.assertIn(r["pq_class"], ("unknown", "not_capable"))       # pqc_only is large too -> stalls
        self.assertEqual(r["probes"]["pqc_only"]["status"], "timeout")
        self.assertEqual(r["pq_class"], "unknown")                     # stall is not a clear "no"

    def test_timeout_is_not_counted_as_not_capable(self):
        bh = F.Blackhole()
        try:
            r = scan(bh.port, timeout=1.0)
        finally:
            bh.close()
        self.assertEqual((r["status"], r["pq_class"], r["primary_probe"]), ("timeout", "unknown", None))
        self.assertNotIn("legacy", r["probes"])                        # timeouts don't escalate to legacy
        self.assertIsNone(r["cert"])
        self.assertEqual(r["probes"]["old_versions"]["status"], "timeout")   # TCP connected, so it's attempted
        self.assertIsNone(r["accepts_tls_1_0_or_1_1"])                       # timeout != "no"

    def test_connect_refused_runs_no_fallbacks(self):
        r = scan(F.free_port())
        self.assertEqual(r["status"], "connect_failed")
        self.assertEqual(set(r["probes"]), {"default", "pqc_only", "old_versions"})
        self.assertEqual(r["pq_class"], "unknown")
        self.assertEqual(r["probes"]["old_versions"], {"status": "skipped", "reason": "tcp_failed"})
        self.assertIsNone(r["accepts_tls_1_0_or_1_1"])


class TestOldVersionsProbe(unittest.TestCase):
    def test_modern_only_server_refuses_old_versions(self):
        """A TLS-1.2+ server (the min_v used across every other test server here) must reject
        a client that offers only TLS 1.0-1.1."""
        with Srv() as s:                                               # default: min TLS1.2 implied by library
            r = scan(s.port)
        self.assertFalse(r["accepts_tls_1_0_or_1_1"])
        self.assertEqual(r["probes"]["old_versions"]["status"], "tls_alert")

    def test_server_that_still_accepts_tls10(self):
        # min AND max pinned to TLS1.0 so the negotiated version is unambiguous; a server that
        # merely allows TLS1.0-and-up would negotiate TLS1.1 against this probe (highest
        # version both sides accept), which is exercised separately below.
        with Srv(min_v=SSL.TLS1_VERSION, max_v=SSL.TLS1_VERSION, seclevel0=True) as s:
            r = scan(s.port)
        self.assertTrue(r["accepts_tls_1_0_or_1_1"])
        self.assertEqual(r["probes"]["old_versions"]["tls_version"], "TLSv1")

    def test_server_allowing_1_0_and_up_negotiates_highest_overlap_with_probe(self):
        """A server with min=TLS1.0 and no ceiling still negotiates TLS1.1 against the
        old_versions probe, because negotiation always picks the highest mutually-supported
        version -- the probe proves 'old versions still accepted', not 'server prefers old'."""
        with Srv(min_v=SSL.TLS1_VERSION, seclevel0=True) as s:          # accepts 1.0 through 1.3
            r = scan(s.port)
        self.assertTrue(r["accepts_tls_1_0_or_1_1"])
        self.assertEqual(r["probes"]["old_versions"]["tls_version"], "TLSv1.1")
        self.assertEqual(r["tls_version"], "TLSv1.3")                   # primary reports its BEST version

    def test_server_that_only_accepts_tls11(self):
        with Srv(min_v=SSL.TLS1_1_VERSION, max_v=SSL.TLS1_1_VERSION, seclevel0=True) as s:
            r = scan(s.port)
        self.assertTrue(r["accepts_tls_1_0_or_1_1"])
        self.assertEqual(r["probes"]["old_versions"]["tls_version"], "TLSv1.1")

    def test_tls12_only_server_also_refuses_old_versions(self):
        with Srv(max_v=SSL.TLS1_2_VERSION) as s:
            r = scan(s.port)
        self.assertEqual(r["tls_version"], "TLSv1.2")
        self.assertFalse(r["accepts_tls_1_0_or_1_1"])                   # best=1.2 does not imply 1.0/1.1 still on

    def test_probe_runs_even_when_reached_via_legacy_fallback(self):
        """The domain's best version IS 1.0 here (found via the `legacy` fallback probe); the
        independent old_versions probe should still run and agree."""
        with Srv(min_v=SSL.TLS1_VERSION, max_v=SSL.TLS1_VERSION, seclevel0=True) as s:
            r = scan(s.port)
        self.assertEqual(r["primary_probe"], "legacy")
        self.assertTrue(r["accepts_tls_1_0_or_1_1"])


class TestCertificates(unittest.TestCase):
    def test_trusted_chain_fields(self):
        with Srv() as s:
            c = scan(s.port)["cert"]
        self.assertTrue(c["trusted"], c["trust_error"])
        self.assertTrue(c["hostname_match"])
        self.assertEqual((c["key_type"], c["key_bits"], c["key_curve"]), ("EC", 256, "secp256r1"))
        self.assertEqual(c["subject_cn"], H)
        self.assertEqual((c["issuer_cn"], c["issuer_o"]), ("Test Root CA", "TestOrg"))
        self.assertEqual(c["sig_hash"], "sha256")
        self.assertIn("ecdsa", c["sig_alg"].lower())
        self.assertFalse(c["expired"] or c["self_signed"])
        self.assertEqual(len(c["leaf_sha256"]), 64)
        self.assertTrue(c["chain_pem"][0].startswith("-----BEGIN CERTIFICATE-----"))

    def test_same_cert_on_shared_host_has_same_fingerprint(self):
        with Srv() as s:
            a, b = scan(s.port, "test.bd")["cert"], scan(s.port, "other.bd")["cert"]
        self.assertEqual(a["leaf_sha256"], b["leaf_sha256"])

    def test_hostname_mismatch(self):
        with Srv() as s:
            c = scan(s.port, host="notlisted.bd")["cert"]
        self.assertFalse(c["hostname_match"])
        self.assertFalse(c["trusted"])

    def test_self_signed(self):
        k, cert = F.make_leaf(None, None, [H], self_signed=True)
        with Srv(k, cert) as s:
            c = scan(s.port)["cert"]
        self.assertTrue(c["self_signed"])
        self.assertFalse(c["trusted"])

    def test_expired(self):
        k, cert = F.make_leaf(CA_KEY, CA, [H], expired=True)
        with Srv(k, cert) as s:
            c = scan(s.port)["cert"]
        self.assertTrue(c["expired"])
        self.assertFalse(c["trusted"])

    def test_weak_rsa_1024_still_recorded(self):
        k, cert = F.make_leaf(CA_KEY, CA, [H], rsa_bits=1024)
        with Srv(k, cert, seclevel0=True) as s:
            r = scan(s.port)
        self.assertEqual(r["status"], "ok")
        self.assertEqual((r["cert"]["key_type"], r["cert"]["key_bits"]), ("RSA", 1024))

    def test_trust_store_skips_bad_roots(self):
        path = os.path.join(TMP, "mixed.pem")
        F.write_pem(path, [CA])
        with open(path, "ab") as f:
            f.write(b"-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n")
        store, info = T.load_trust_store_with_info(path)
        self.assertEqual((info["roots_loaded"], info["roots_skipped"]), (1, 1))
        with Srv() as s:
            self.assertTrue(T.scan_domain(H, "127.0.0.1", CTXS, store, port=s.port, timeout=3)["cert"]["trusted"])

    def test_untrusted_against_real_roots(self):
        real = T.load_trust_store()                                    # certifi: test CA is not in it
        with Srv() as s:
            r = T.scan_domain(H, "127.0.0.1", CTXS, real, port=s.port, timeout=3)
        self.assertFalse(r["cert"]["trusted"])


class TestCertParsingIsolation(unittest.TestCase):
    """The 2026-09-19 real scan hit two cryptography warnings on real .bd certificates
    (malformed Name attribute; non-positive serial number, an RFC 5280 violation the library
    says will become a hard exception in a future release). These tests prove: (1) a genuine
    malformed-but-real-world certificate is captured as DATA, not just silenced, and (2) a
    handshake that succeeded can never be turned into a lost/"error" record by anything that
    goes wrong afterwards while handling the certificate."""

    def test_malformed_name_attribute_captured_not_crashed(self):
        k, cert = F.make_leaf_with_bad_country_code(CA_KEY, CA, [H])
        with Srv(k, cert) as s:
            import warnings
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                r = scan(s.port)
        self.assertEqual([str(x.message) for x in w], [])              # not printed to the console
        self.assertEqual(r["status"], "ok")                             # handshake unaffected
        self.assertEqual(r["tls_version"], "TLSv1.3")
        c = r["cert"]
        self.assertIn("parse_warnings", c)
        self.assertTrue(any("length must be" in m for m in c["parse_warnings"]))
        self.assertEqual(c["subject_cn"], H)                            # the rest of parsing still worked
        self.assertIn("serial_number", c)
        self.assertFalse(c["serial_number_non_positive"])               # this cert's serial is fine

    def test_chain_retrieval_exception_does_not_lose_a_successful_handshake(self):
        """Simulates cryptography's warning becoming a hard exception in a future release."""
        from unittest import mock
        with Srv() as s:
            with mock.patch.object(SSL.Connection, "get_peer_cert_chain", side_effect=RuntimeError("simulated future break")):
                r, chain = T.handshake(CTXS["default"], H, "127.0.0.1", s.port, timeout=3)
        self.assertEqual(r["status"], "ok")                             # NOT "error" -- this is the whole point
        self.assertEqual(r["tls_version"], "TLSv1.3")
        self.assertEqual(r["group"], "X25519MLKEM768")
        self.assertIn("simulated future break", r["chain_error"])
        self.assertIsNone(chain)

    def test_analyze_chain_field_exception_still_returns_a_dict(self):
        with Srv() as s:
            r, chain = T.handshake(CTXS["default"], H, "127.0.0.1", s.port, timeout=3)
        from unittest import mock
        with mock.patch.object(T, "_key_info", side_effect=RuntimeError("boom")):
            cert = T.analyze_chain(H, chain, STORE)
        self.assertIsInstance(cert, dict)
        self.assertIn("parse_error", cert)
        self.assertEqual(cert["chain_len"], len(chain))                 # what parsed before the crash is kept


class TestPolitenessAndControl(unittest.TestCase):
    def test_per_ip_cap_is_respected(self):
        """Concurrency is measured INSIDE the gate (what the scanner controls). A server-side count
        overshoots by one because the server notices a close slightly after the client moves on."""
        import contextlib
        from importlib import util
        spec = util.spec_from_file_location("b1", os.path.join(BASE, "measurement", "phase_b_tls", "b1_tls_handshake_scan.py"))
        b1 = util.module_from_spec(spec)
        spec.loader.exec_module(b1)

        class CountingGate(b1.Gate):
            def __init__(self, *a):
                super().__init__(*a)
                self.active = self.peak = 0
                self.l = threading.Lock()

            @contextlib.contextmanager
            def __call__(self, ip):
                with super().__call__(ip):
                    with self.l:
                        self.active += 1
                        self.peak = max(self.peak, self.active)
                    try:
                        yield
                    finally:
                        with self.l:
                            self.active -= 1

        with Srv(hold=0.15) as s:
            gate = CountingGate(2, 0)
            with ThreadPoolExecutor(12) as pool:
                list(pool.map(lambda i: scan(s.port, gate=gate), range(12)))
            accepted = s.accepted
        self.assertEqual(accepted, 24)              # PQ-default -> default + old_versions = 2 handshakes each
        self.assertEqual(gate.peak, 2)                                 # cap never exceeded despite that

    def test_gate_caps_per_ip_not_globally(self):
        from importlib import util
        spec = util.spec_from_file_location("b1", os.path.join(BASE, "measurement", "phase_b_tls", "b1_tls_handshake_scan.py"))
        b1 = util.module_from_spec(spec)
        spec.loader.exec_module(b1)
        g = b1.Gate(1, 0)
        with g("10.0.0.1"):
            done = threading.Event()
            threading.Thread(target=lambda: (g("10.0.0.2").__enter__(), done.set()), daemon=True).start()
            self.assertTrue(done.wait(1), "a different IP must not wait for 10.0.0.1's permit")

    def test_control_passes_only_for_trusted_pq(self):
        with Srv() as s:
            _, ok = T.control_check([H], CTXS, STORE, port=s.port, timeout=3, resolve=lambda h: "127.0.0.1")
        self.assertTrue(ok)
        with Srv(groups="X25519:secp256r1") as s:
            _, ok = T.control_check([H], CTXS, STORE, port=s.port, timeout=3, resolve=lambda h: "127.0.0.1")
        self.assertFalse(ok)                                           # classical-only control must fail
        k, cert = F.make_leaf(None, None, [H], self_signed=True)
        with Srv(k, cert) as s:
            res, ok = T.control_check([H], CTXS, STORE, port=s.port, timeout=3, resolve=lambda h: "127.0.0.1")
        self.assertFalse(ok)                                           # PQ but untrusted (interception)
        self.assertEqual(res[H]["group"], "X25519MLKEM768")

    def test_control_resolve_failure(self):
        def boom(h):
            raise OSError("no dns")
        res, ok = T.control_check(["x.invalid"], CTXS, STORE, resolve=boom)
        self.assertFalse(ok)
        self.assertEqual(res["x.invalid"]["status"], "resolve_failed")


class TestEndToEnd(unittest.TestCase):
    """b1's real main() in a temp copy of the project, against one local PQ server."""

    DOMAINS = ["test.bd", "other.bd", "third.bd"]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.proj = os.path.join(cls.tmp, "proj")
        for sub in ("measurement", "tests"):
            shutil.copytree(os.path.join(BASE, sub), os.path.join(cls.proj, sub),
                            ignore=shutil.ignore_patterns("__pycache__"))
        key, cert = F.make_leaf(CA_KEY, CA, cls.DOMAINS)
        cls.srv = F.TLSServer(key, cert)
        run = os.path.join(cls.proj, "data", "measurement", "runs", "run_test", "raw")
        os.makedirs(run)
        os.makedirs(os.path.join(cls.proj, "data", "measurement", "processed"))
        with open(os.path.join(run, "port443.jsonl"), "w") as f:
            for d in cls.DOMAINS + ["closed.bd"]:
                f.write(json.dumps({"domain": d, "port443": "closed" if d == "closed.bd" else "open"}) + "\n")
        cls.write_live(cls.DOMAINS)

    @classmethod
    def write_live(cls, domains):
        with open(os.path.join(cls.proj, "data", "measurement", "processed", "live_domains.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "sector", "category", "tier", "ip", "family"])
            for d in domains:
                w.writerow([d, "x", "x", "verified", "127.0.0.1", "4"])

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def b1(self, *extra):
        cmd = [sys.executable, "tests/run_b1_with_fakes.py", str(self.srv.port), "--run-id", "run_test",
               "--skip-control", "--trust-store", CA_PEM, *extra]
        return subprocess.run(cmd, cwd=self.proj, capture_output=True, text=True)

    def test_1_full_run_and_resume(self):
        p = self.b1()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        out = os.path.join(self.proj, "data", "measurement", "runs", "run_test", "raw", "tls.jsonl")
        with open(out) as f:
            recs = [json.loads(l) for l in f]
        self.assertEqual(sorted(r["domain"] for r in recs), sorted(self.DOMAINS))
        self.assertTrue(all(r["pq_class"] == "pq_default" and r["cert"]["trusted"] for r in recs))
        self.assertTrue(all(r["family"] == "4" and r["ts"] for r in recs))
        p = self.b1()
        self.assertIn("to do 0", p.stdout)
        with open(os.path.join(self.proj, "data", "measurement", "runs", "run_test", "run_meta.json")) as f:
            meta = json.load(f)["tls"]
        self.assertIn("X25519MLKEM768", meta["libraries"]["pqc_groups_offered"])
        self.assertEqual(len(meta["input"]["sha256"]), 64)
        self.assertEqual(meta["groups"]["default"], T.DEFAULT_GROUPS)

    def test_2_mismatched_live_list_aborts(self):
        self.write_live(self.DOMAINS[:2])                              # one open domain missing
        try:
            p = self.b1()
        finally:
            self.write_live(self.DOMAINS)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("does not match this run", p.stderr + p.stdout)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)