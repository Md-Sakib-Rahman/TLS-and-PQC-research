#!/usr/bin/env python3
"""
Tests for c2 (legacy cipher inference). Cipher names below are REAL OpenSSL suite names,
confirmed present in the bundled OpenSSL's ALL:@SECLEVEL=0 list (checked directly before writing
this module -- see its docstring), not invented. Run: python tests/test_phase_c2.py
"""
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)

from measurement.phase_c_derived import c2_legacy_cipher_inference as C2

# Real cipher names, confirmed compiled into the bundled OpenSSL (checked via SSL_get_cipher_list).
AEAD = ["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", "AES128-CCM", "TLS_AES_128_GCM_SHA256"]
CBC = ["ECDHE-ECDSA-AES128-SHA", "ECDHE-RSA-AES256-SHA", "AES128-SHA", "ECDHE-RSA-CAMELLIA256-SHA384",
       "DHE-RSA-SEED-SHA"]
STREAM_OR_NULL = ["ECDHE-RSA-NULL-SHA", "NULL-SHA256", "PSK-NULL-SHA"]     # RC4 removed from this build; NULL remains
IDEA_CIPHER = "IDEA-CBC-SHA"                                                # the one Sweet32-class cipher that survives


class TestCipherClassification(unittest.TestCase):
    def test_aead_is_not_cbc(self):
        for c in AEAD:
            self.assertFalse(C2.is_cbc_mode(c), c)

    def test_real_cbc_ciphers_from_actual_scan_and_library(self):
        for c in CBC:
            self.assertTrue(C2.is_cbc_mode(c), c)

    def test_null_and_stream_are_not_cbc(self):
        for c in STREAM_OR_NULL:
            self.assertFalse(C2.is_cbc_mode(c), c)

    def test_none_cipher(self):
        self.assertIsNone(C2.is_cbc_mode(None))
        self.assertIsNone(C2.is_cbc_mode(""))

    def test_idea_detection(self):
        self.assertTrue(C2.IDEA_RE.search(IDEA_CIPHER))
        for c in AEAD + CBC:
            self.assertFalse(C2.IDEA_RE.search(c), c)


class TestClassifyRow(unittest.TestCase):
    def base(self, cipher=None, version=None, ov_status="ok", ov_cipher=None, ov_version=None):
        return {"domain": "a.bd", "ip": "1.1.1.1", "category": "university", "tier": "verified",
                "is_service_hostname": "False", "cipher": cipher, "tls_version": version,
                "probes": {"old_versions": {"status": ov_status, "cipher": ov_cipher, "tls_version": ov_version}}}

    def test_real_scan_example_lucky13_exposed(self):
        # Exactly the shape confirmed from the user's real tls.jsonl: old_versions succeeded with a CBC cipher.
        r = C2.classify(self.base(cipher="X25519MLKEM768", version="TLSv1.3",
                                  ov_cipher="ECDHE-ECDSA-AES128-SHA", ov_version="TLSv1.1"))
        self.assertTrue(r["lucky13_beast_exposed"])
        self.assertFalse(r["idea_negotiated"])
        self.assertFalse(r["des3_probed"])          # no c2b data supplied -> never "tested"
        self.assertFalse(r["poodle_tested"])
        self.assertIsNone(r["accepts_sslv3"])
        self.assertIsNone(r["accepts_3des"])

    def test_old_versions_aead_not_possible_but_defensive(self):
        # AEAD ciphers are TLS 1.2+/1.3-only in practice; still verify the classifier doesn't flag one.
        r = C2.classify(self.base(cipher="ECDHE-RSA-AES128-GCM-SHA256", version="TLSv1.2",
                                  ov_cipher="ECDHE-RSA-AES128-GCM-SHA256", ov_version="TLSv1.1"))
        self.assertFalse(r["lucky13_beast_exposed"])

    def test_old_versions_never_succeeded(self):
        r = C2.classify(self.base(cipher="ECDHE-RSA-AES128-GCM-SHA256", version="TLSv1.3",
                                  ov_status="tls_alert", ov_cipher=None, ov_version=None))
        self.assertIsNone(r["lucky13_beast_exposed"])
        self.assertFalse(r["idea_negotiated"])

    def test_idea_on_primary_handshake(self):
        r = C2.classify(self.base(cipher="IDEA-CBC-SHA", version="TLSv1.2", ov_status="tls_alert"))
        self.assertTrue(r["idea_negotiated"])

    def test_no_tcp_at_all(self):
        row = self.base(cipher=None, version=None, ov_status="skipped", ov_cipher=None, ov_version=None)
        row["probes"]["old_versions"] = {"status": "skipped", "reason": "tcp_failed"}
        r = C2.classify(row)
        self.assertIsNone(r["lucky13_beast_exposed"])
        self.assertFalse(r["idea_negotiated"])


class TestEndToEnd(unittest.TestCase):
    """
    10.0.0.1: u1 (university) primary=PQ TLS1.3, old_versions=ECDHE-ECDSA-AES128-SHA (Lucky13 exposed)
    10.0.0.1: u2 (university) primary=PQ TLS1.3, old_versions=ECDHE-RSA-AES128-GCM-SHA256 (AEAD, not exposed)
    10.0.0.2: g1 (government) primary=IDEA-CBC-SHA, old_versions never completed (tls_alert)
    10.0.0.2: g2 (government) primary=classical, old_versions=tls_alert (refuses old versions)
    University Lucky13: 1/2 domains, both on one server -> per-server 50%.
    Government idea_negotiated: 1/2 domains.
    """
    LIVE = [("u1", "university", "10.0.0.1"), ("u2", "university", "10.0.0.1"),
            ("g1", "government", "10.0.0.2"), ("g2", "government", "10.0.0.2")]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        proj = cls.proj = os.path.join(cls.tmp, "proj")
        shutil.copytree(os.path.join(BASE, "measurement"), os.path.join(proj, "measurement"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        raw = os.path.join(proj, "data", "measurement", "runs", "r", "raw")
        proc = os.path.join(proj, "data", "measurement", "processed")
        os.makedirs(raw)
        os.makedirs(proc)
        with open(os.path.join(proc, "phase_b_domains.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "category", "tier", "ip", "is_service_hostname"])
            for d, c, ip in cls.LIVE:
                w.writerow([d, c, "verified", ip, "False"])
        recs = [
            {"domain": "u1", "cipher": "X25519MLKEM768", "tls_version": "TLSv1.3",
             "probes": {"old_versions": {"status": "ok", "cipher": "ECDHE-ECDSA-AES128-SHA", "tls_version": "TLSv1.1"}}},
            {"domain": "u2", "cipher": "X25519MLKEM768", "tls_version": "TLSv1.3",
             "probes": {"old_versions": {"status": "ok", "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "tls_version": "TLSv1.1"}}},
            {"domain": "g1", "cipher": "IDEA-CBC-SHA", "tls_version": "TLSv1.2",
             "probes": {"old_versions": {"status": "tls_alert"}}},
            {"domain": "g2", "cipher": "ECDHE-RSA-AES256-SHA", "tls_version": "TLSv1.2",
             "probes": {"old_versions": {"status": "tls_alert"}}},
        ]
        with open(os.path.join(raw, "tls.jsonl"), "w") as f:
            f.write("".join(json.dumps(r) + "\n" for r in recs))
        cls.p = subprocess.run([sys.executable, "measurement/phase_c_derived/c2_legacy_cipher_inference.py",
                               "--run-id", "r"], cwd=proj, capture_output=True, text=True)

        def load(name):
            with open(os.path.join(proj, "results", "tables", name), newline="") as f:
                return {r["group"]: r for r in csv.DictReader(f)}
        if cls.p.returncode == 0:
            cls.cat = load("phase_c2_by_category.csv")
            with open(os.path.join(proj, "results", "tables", "phase_c2_report.md")) as f:
                cls.md = f.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_0_ran(self):
        self.assertEqual(self.p.returncode, 0, self.p.stdout + self.p.stderr)

    def test_university_lucky13(self):
        u = self.cat["university"]
        self.assertEqual((u["lucky13_beast_exposed_n"], u["lucky13_beast_exposed_den"],
                          u["lucky13_beast_exposed_dom_pct"], u["lucky13_beast_exposed_srv_pct"]),
                         ("1", "2", "50.0", "50.0"))

    def test_government_idea(self):
        g = self.cat["government"]
        self.assertEqual((g["idea_negotiated_n"], g["idea_negotiated_den"]), ("1", "2"))
        self.assertEqual((g["lucky13_beast_exposed_n"], g["lucky13_beast_exposed_den"]), ("0", "0"))

    def test_report_carries_the_structural_lucky13_caveat(self):
        self.assertIn("structurally near-100%", self.md)
        self.assertIn("NOT an independent server-behaviour", self.md)
        self.assertIn("accepts_tls_1_0_or_1_1` -- cite that", self.md)

    def test_report_without_c2b_says_not_tested(self):
        self.assertIn("c2b has not been run", self.md)
        # the disclaimer must be the only place "0 vulnerable" appears
        self.assertIn("Not reported as '0 vulnerable'", self.md)
        self.assertEqual(self.md.count("0 vulnerable"), 1)
        self.assertNotIn("Accepts SSLv3", self.md)          # no legacy columns without legacy data


class TestLegacyResultsJoin(unittest.TestCase):
    def base(self):
        return {"domain": "a.bd", "ip": "1.1.1.1", "category": "university", "tier": "verified",
                "is_service_hostname": "False", "cipher": "X25519MLKEM768", "tls_version": "TLSv1.3",
                "probes": {"old_versions": {"status": "tls_alert"}}}

    def test_sslv3_is_per_ip_and_3des_per_domain(self):
        r = C2.classify(self.base(),
                        {"accepts_sslv3": True, "poodle_exposed": True, "offer_all": {"status": "accepted", "cipher": "AES128-SHA"}},
                        {"accepts_3des": False, "status": "refused"})
        self.assertEqual((r["accepts_sslv3"], r["poodle_exposed"], r["sslv3_cipher"]), (True, True, "AES128-SHA"))
        self.assertEqual((r["accepts_3des"], r["poodle_tested"], r["des3_probed"]), (False, True, True))

    def test_inconclusive_stays_none_not_false(self):
        r = C2.classify(self.base(), {"accepts_sslv3": None, "poodle_exposed": None, "offer_all": {"status": "timeout"}},
                        {"accepts_3des": None, "status": "timeout"})
        self.assertIsNone(r["accepts_sslv3"])
        self.assertFalse(r["poodle_tested"])
        self.assertFalse(r["des3_probed"])


class TestEndToEndWithLegacy(unittest.TestCase):
    """
    10.0.0.1: u1, u2 (university)  SSLv3 per IP: accepted + POODLE-exposed (one record covers both)
                                   3DES: u1 accepted, u2 refused
    10.0.0.2: g1 (government)      SSLv3 refused; 3DES probe timed out (inconclusive -> excluded)
    10.0.0.3: g2 (government)      no legacy records at all (deferred / unreachable) -> excluded
    University: accepts_sslv3 2/2 domains, per server 1/1 = 100%; POODLE 2/2; 3DES 1/2 = 50%
    Government: accepts_sslv3 0/1; poodle 0/1; accepts_3des 0/0 (nothing conclusive)
    """
    LIVE = [("u1", "university", "10.0.0.1"), ("u2", "university", "10.0.0.1"),
            ("g1", "government", "10.0.0.2"), ("g2", "government", "10.0.0.3")]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        proj = cls.proj = os.path.join(cls.tmp, "proj")
        shutil.copytree(os.path.join(BASE, "measurement"), os.path.join(proj, "measurement"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        raw = os.path.join(proj, "data", "measurement", "runs", "r", "raw")
        proc = os.path.join(proj, "data", "measurement", "processed")
        os.makedirs(raw)
        os.makedirs(proc)
        with open(os.path.join(proc, "phase_b_domains.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "category", "tier", "ip", "is_service_hostname"])
            for d, c, ip in cls.LIVE:
                w.writerow([d, c, "verified", ip, "False"])
        with open(os.path.join(raw, "tls.jsonl"), "w") as f:
            for d, _, _ in cls.LIVE:
                f.write(json.dumps({"domain": d, "cipher": "X25519MLKEM768", "tls_version": "TLSv1.3",
                                    "probes": {"old_versions": {"status": "tls_alert"}}}) + "\n")
        with open(os.path.join(raw, "legacy_sslv3_ip.jsonl"), "w") as f:
            f.write(json.dumps({"ip": "10.0.0.1", "accepts_sslv3": True, "poodle_exposed": True,
                                "offer_all": {"status": "accepted", "cipher": "DHE-RSA-AES256-SHA"}}) + "\n")
            f.write(json.dumps({"ip": "10.0.0.2", "accepts_sslv3": False, "poodle_exposed": False,
                                "offer_all": {"status": "refused"}}) + "\n")
        with open(os.path.join(raw, "legacy_3des.jsonl"), "w") as f:
            f.write(json.dumps({"domain": "u1", "ip": "10.0.0.1", "status": "accepted", "accepts_3des": True,
                                "protocol": "TLSv1", "cipher": "DES-CBC3-SHA"}) + "\n")
            f.write(json.dumps({"domain": "u2", "ip": "10.0.0.1", "status": "refused", "accepts_3des": False}) + "\n")
            f.write(json.dumps({"domain": "g1", "ip": "10.0.0.2", "status": "timeout", "accepts_3des": None}) + "\n")
        cls.p = subprocess.run([sys.executable, "measurement/phase_c_derived/c2_legacy_cipher_inference.py",
                               "--run-id", "r"], cwd=proj, capture_output=True, text=True)

        def load(name):
            with open(os.path.join(proj, "results", "tables", name), newline="") as f:
                return {r["group"]: r for r in csv.DictReader(f)}
        if cls.p.returncode == 0:
            cls.cat = load("phase_c2_by_category.csv")
            with open(os.path.join(proj, "data", "measurement", "processed", "phase_c2_ciphers.csv"), newline="") as f:
                cls.dom = {r["domain"]: r for r in csv.DictReader(f)}
            with open(os.path.join(proj, "results", "tables", "phase_c2_report.md")) as f:
                cls.md = f.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_0_ran(self):
        self.assertEqual(self.p.returncode, 0, self.p.stdout + self.p.stderr)

    def test_university(self):
        u = self.cat["university"]
        self.assertEqual((u["accepts_sslv3_n"], u["accepts_sslv3_den"], u["accepts_sslv3_dom_pct"], u["accepts_sslv3_srv_pct"]),
                         ("2", "2", "100.0", "100.0"))
        self.assertEqual((u["poodle_exposed_n"], u["poodle_exposed_den"]), ("2", "2"))
        self.assertEqual((u["accepts_3des_n"], u["accepts_3des_den"], u["accepts_3des_dom_pct"]), ("1", "2", "50.0"))

    def test_government_inconclusive_excluded(self):
        g = self.cat["government"]
        self.assertEqual((g["accepts_sslv3_n"], g["accepts_sslv3_den"]), ("0", "1"))     # g2 has no result at all
        self.assertEqual((g["accepts_3des_n"], g["accepts_3des_den"]), ("0", "0"))       # g1 timed out -> excluded
        self.assertEqual((self.dom["g1"]["accepts_3des"], self.dom["g2"]["accepts_sslv3"]), ("", ""))

    def test_per_domain_columns(self):
        self.assertEqual((self.dom["u1"]["sslv3_cipher"], self.dom["u1"]["des3_protocol"], self.dom["u1"]["des3_cipher"]),
                         ("DHE-RSA-AES256-SHA", "TLSv1", "DES-CBC3-SHA"))
        self.assertEqual((self.dom["u2"]["accepts_sslv3"], self.dom["u2"]["poodle_exposed"]), ("True", "True"))

    def test_lucky13_caveat_present_with_c2b_data_too(self):
        self.assertIn("structurally near-100%", self.md)

    def test_report_switches_to_measured_wording(self):
        self.assertIn("measured by c2b", self.md)
        self.assertIn("accepts 3DES when offered", self.md)
        self.assertIn("POODLE over TLS", self.md)
        self.assertNotIn("c2b has not been run", self.md)
        self.assertIn("SSLv3 answered for 3 of 4 domains, 3DES for 2", self.md)
        self.assertNotIn("0 vulnerable", self.md)


if __name__ == "__main__":
    unittest.main(verbosity=2)