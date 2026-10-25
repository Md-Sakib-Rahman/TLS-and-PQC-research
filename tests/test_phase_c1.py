#!/usr/bin/env python3
"""Tests for c1 (key-size compliance). Real generated certificates for the chain logic;
hand-computed expected values for the tables. Run: python tests/test_phase_c1.py"""
import csv
import datetime
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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from measurement.phase_c_derived import c1_keysize_compliance as C1


def cert_pem(key, signer=None):
    signer = signer or key
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.bd")])
    now = datetime.datetime.now(datetime.timezone.utc)
    algo = None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now)
         .not_valid_after(now + datetime.timedelta(days=30)).sign(signer, algo))
    return c.public_bytes(serialization.Encoding.PEM).decode()


RSA1024 = rsa.generate_private_key(65537, 1024)
RSA2048 = rsa.generate_private_key(65537, 2048)
P256 = ec.generate_private_key(ec.SECP256R1())
P384 = ec.generate_private_key(ec.SECP384R1())


class TestStrengthTable(unittest.TestCase):
    def test_rsa(self):
        for bits, t in [(512, "<80"), (1024, "80"), (2047, "80"), (2048, "112"), (3072, "128"),
                        (4096, "128"), (7680, "192"), (8192, "192"), (15360, "256")]:
            self.assertEqual(C1.strength("RSA", bits), t, bits)

    def test_ec_and_eddsa(self):
        for bits, t in [(192, "80"), (224, "112"), (256, "128"), (384, "192"), (521, "256")]:
            self.assertEqual(C1.strength("EC", bits), t, bits)
        self.assertEqual(C1.strength("Ed25519", 256), "128")
        self.assertEqual(C1.strength("Ed448", 456), "192")

    def test_unknown(self):
        self.assertIsNone(C1.strength(None, 2048))
        self.assertIsNone(C1.strength("RSA", None))
        self.assertIsNone(C1.strength("X25519Weird", 256))

    def test_status(self):
        self.assertEqual([C1.status(t) for t in ["<80", "80", "112", "128", "256", None]],
                         ["below_112", "below_112", "only_112", "128_plus", "128_plus", None])


class TestChainAndClassify(unittest.TestCase):
    def test_chain_weakest_real_certs(self):
        self.assertEqual(C1.chain_weakest([cert_pem(P256), cert_pem(RSA1024)]), "80")
        self.assertEqual(C1.chain_weakest([cert_pem(P384), cert_pem(RSA2048)]), "112")
        self.assertEqual(C1.chain_weakest([cert_pem(ed25519.Ed25519PrivateKey.generate())]), "128")
        self.assertIsNone(C1.chain_weakest(None))
        self.assertEqual(C1.chain_weakest(["not a pem", cert_pem(P256)]), "128")   # bad entry skipped

    def row(self):
        return {"domain": "a.bd", "category": "government", "tier": "verified", "ip": "1.1.1.1",
                "is_service_hostname": "False"}

    def test_weak_hash_and_pq_oid_from_recorded_fields(self):
        r = C1.classify(self.row(), {"cert": {"key_type": "RSA", "key_bits": 2048, "sig_hash": "sha1",
                                              "sig_alg": "sha1WithRSAEncryption", "sig_alg_oid": "1.2.840.113549.1.1.5"}})
        self.assertTrue(r["weak_sig_hash"])
        self.assertEqual((r["leaf_strength"], r["leaf_status"], r["pq_signature"], r["quantum_vulnerable"]),
                         ("112", "only_112", "", True))
        r = C1.classify(self.row(), {"cert": {"key_type": "EC", "key_bits": 256, "sig_hash": None,
                                              "sig_alg_oid": "2.16.840.1.101.3.4.3.18"}})
        self.assertEqual((r["pq_signature"], r["quantum_vulnerable"], r["weak_sig_hash"]), ("ML-DSA-65", False, False))

    def test_no_certificate(self):
        self.assertFalse(C1.classify(self.row(), {"status": "timeout", "cert": None})["has_cert"])
        self.assertFalse(C1.classify(self.row(), None)["has_cert"])


class TestEndToEnd(unittest.TestCase):
    """
    10.0.0.1: g1, g2, g3 (government) -- RSA-1024 leaf (below_112)
    10.0.0.2: g4 (government)         -- RSA-2048 leaf, chain has RSA-1024 intermediate
    10.0.0.3: u1 (university)         -- P-256 leaf; cpanel.u1 (university, service) -- P-256
    10.0.0.4: u2 (university)         -- handshake failed, no certificate
    Government leaf below 112: 3/4 per domain; per server (1 + 0)/2 = 50.0%.
    Government chain below 112: 4/4 = 100% (g4's intermediate is 80-bit).
    ALL with cert: 6 of 7. University leaf 128+: 2/2.
    Excluding service hostnames: university has 2 domains (u1, u2), 1 with a cert.
    """
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
        doms = [("g1", "government", "10.0.0.1", False), ("g2", "government", "10.0.0.1", False),
                ("g3", "government", "10.0.0.1", False), ("g4", "government", "10.0.0.2", False),
                ("u1", "university", "10.0.0.3", False), ("cpanel.u1", "university", "10.0.0.3", True),
                ("u2", "university", "10.0.0.4", False)]
        with open(os.path.join(proc, "phase_b_domains.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "category", "tier", "ip", "is_service_hostname"])
            for d, c, ip, s in doms:
                w.writerow([d, c, "verified", ip, s])
        rsa1024 = {"key_type": "RSA", "key_bits": 1024, "sig_hash": "sha256", "sig_alg": "sha256WithRSAEncryption",
                   "sig_alg_oid": "1.2.840.113549.1.1.11", "chain_pem": [cert_pem(RSA1024)]}
        rsa2048 = {"key_type": "RSA", "key_bits": 2048, "sig_hash": "sha256", "sig_alg": "sha256WithRSAEncryption",
                   "sig_alg_oid": "1.2.840.113549.1.1.11", "chain_pem": [cert_pem(RSA2048), cert_pem(RSA1024)]}
        p256 = {"key_type": "EC", "key_bits": 256, "key_curve": "secp256r1", "sig_hash": "sha256",
                "sig_alg": "ecdsa-with-SHA256", "sig_alg_oid": "1.2.840.10045.4.3.2", "chain_pem": [cert_pem(P256)]}
        recs = [{"domain": d, "status": "ok", "cert": rsa1024, "ts": "t"} for d in ("g1", "g2", "g3")] + [
            {"domain": "g4", "status": "ok", "cert": rsa2048, "ts": "t"},
            {"domain": "u1", "status": "ok", "cert": p256, "ts": "t"},
            {"domain": "cpanel.u1", "status": "ok", "cert": p256, "ts": "t"},
            {"domain": "u2", "status": "timeout", "cert": None, "ts": "t"}]
        with open(os.path.join(raw, "tls.jsonl"), "w") as f:
            f.write("".join(json.dumps(r) + "\n" for r in recs))
        cls.p = subprocess.run([sys.executable, "measurement/phase_c_derived/c1_keysize_compliance.py", "--run-id", "r"],
                               cwd=proj, capture_output=True, text=True)

        def load(name):
            with open(os.path.join(proj, "results", "tables", name), newline="") as f:
                return {r["group"]: r for r in csv.DictReader(f)}
        if cls.p.returncode == 0:
            cls.cat = load("phase_c1_by_category.csv")
            with open(os.path.join(proj, "data", "measurement", "processed", "phase_c1_keys.csv"), newline="") as f:
                cls.keys = {r["domain"]: r for r in csv.DictReader(f)}
            with open(os.path.join(proj, "results", "tables", "phase_c1_report.md")) as f:
                cls.md = f.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_0_ran(self):
        self.assertEqual(self.p.returncode, 0, self.p.stdout + self.p.stderr)

    def test_government(self):
        g = self.cat["government"]
        self.assertEqual((g["leaf_below_112_n"], g["leaf_below_112_den"], g["leaf_below_112_dom_pct"],
                          g["leaf_below_112_srv_pct"]), ("3", "4", "75.0", "50.0"))
        self.assertEqual((g["chain_below_112_n"], g["chain_below_112_den"]), ("4", "4"))

    def test_university_and_all(self):
        u, a = self.cat["university"], self.cat["ALL"]
        self.assertEqual((u["leaf_128_plus_n"], u["leaf_128_plus_den"], u["with_certificate"]), ("2", "2", "2"))
        self.assertEqual((a["domains"], a["with_certificate"], a["pq_signature_n"]), ("7", "6", "0"))
        self.assertEqual(self.keys["u2"]["has_cert"], "False")
        self.assertEqual(self.keys["g4"]["chain_weakest_strength"], "80")

    def test_report_excludes_service(self):
        self.assertIn("Excluding service hostnames (1 removed)", self.md)
        self.assertIn("| RSA | 80 | 3 |", self.md)


if __name__ == "__main__":
    unittest.main(verbosity=2)