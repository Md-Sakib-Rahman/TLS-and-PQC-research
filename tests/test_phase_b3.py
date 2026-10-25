#!/usr/bin/env python3
"""
Tests for b3 (Phase B aggregation). Synthetic data with hand-computed expected values.
Run from project root:  python tests/test_phase_b3.py

Scenario (8 live domains, 4 IPs):
  10.0.0.1  u1-u4 university/verified   TLS pq_default, refuses old versions, certs trusted (EC)
            HTTP: u1 ok+HSTS, u2 ok no HSTS, u3/u4 PENDING (no record)
  10.0.0.2  u5 university/unverified    TLS not_capable, accepts old versions,
            cert untrusted+expired RSA-1024; HTTP ok no HSTS. Also an OLDER duplicate tls
            record saying pq_default, which must be ignored.
  10.0.0.3  g1 government/verified      TLS pq_default, old-version probe inconclusive (None),
            HTTP ok+HSTS+Cloudflare
            g2 government/verified      TLS not_capable, refuses old; no cert; HTTP timeout
            (a real scanned failure, NOT pending)
  10.0.0.4  g3 government/unverified    NO TLS record (not_scanned); HTTP ok+HSTS
  plus one tls record for a domain outside the live set (must be ignored)
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

from measurement.phase_b_tls import b3_parse_results as B3

LIVE = [("u1", "university", "verified", "10.0.0.1"), ("u2", "university", "verified", "10.0.0.1"),
        ("u3", "university", "verified", "10.0.0.1"), ("u4", "university", "verified", "10.0.0.1"),
        ("u5", "university", "unverified", "10.0.0.2"),
        ("g1", "government", "verified", "10.0.0.3"), ("g2", "government", "verified", "10.0.0.3"),
        ("g3", "government", "unverified", "10.0.0.4")]

EC_OK = {"trusted": True, "expired": False, "self_signed": False, "hostname_match": True,
         "key_type": "EC", "key_bits": 256, "sig_hash": "sha256", "issuer_o": "Let's Encrypt"}


def tls(d, ip, pq, old, cert, ts="2026-09-20T00:00:00", version="TLSv1.3"):
    return {"domain": d, "ip": ip, "status": "ok", "tls_version": version, "cipher": "X",
            "group": "X25519MLKEM768" if pq == "pq_default" else "x25519", "pq_class": pq,
            "pq_intolerant": False, "legacy_only": False, "accepts_tls_1_0_or_1_1": old,
            "cert": cert, "ts": ts}


def http(d, ip, hsts=None, waf=None, status="ok", source=None):
    r = {"domain": d, "ip": ip, "status": status, "ts": "2026-09-23T00:00:00"}
    if status == "ok":
        r.update({"status_code": 200, "hsts": {"present": bool(hsts), "max_age": 100 if hsts else None},
                  "waf": {"detected": bool(waf), "vendors": waf or []}})
    else:
        r.update({"hsts": None, "waf": None})
    if source:
        r["source"] = source
    return r


TLS_RECS = [tls(d, "10.0.0.1", "pq_default", False, EC_OK) for d in ("u1", "u2", "u3", "u4")] + [
    tls("u5", "10.0.0.2", "pq_default", False, EC_OK, ts="2026-09-19T00:00:00"),        # older duplicate
    tls("u5", "10.0.0.2", "not_capable", True,
        {"trusted": False, "expired": True, "self_signed": False, "hostname_match": True,
         "key_type": "RSA", "key_bits": 1024, "sig_hash": "sha256", "issuer_o": "Old CA"}),
    tls("g1", "10.0.0.3", "pq_default", None, EC_OK),
    tls("g2", "10.0.0.3", "not_capable", False, None),
    tls("outside.bd", "10.9.9.9", "pq_default", False, EC_OK),
]
HTTP_RECS = [http("u1", "10.0.0.1", hsts=True), http("u2", "10.0.0.1", hsts=False, source="secondary_vantage"),
             http("u5", "10.0.0.2", hsts=False), http("g1", "10.0.0.3", hsts=True, waf=["Cloudflare"]),
             http("g2", "10.0.0.3", status="timeout"), http("g3", "10.0.0.4", hsts=True)]


class TestServerWeighting(unittest.TestCase):
    def test_each_ip_counts_once(self):
        rows = [{"ip": "a", "x": True}, {"ip": "a", "x": True}, {"ip": "a", "x": True}, {"ip": "b", "x": False}]
        pct_, n = B3.server_weighted(rows, lambda r: True, lambda r: r["x"])
        self.assertEqual((pct_, n), (50.0, 2))            # per-domain would be 75%

    def test_split_within_ip(self):
        rows = [{"ip": "a", "x": True}, {"ip": "a", "x": False}]
        self.assertEqual(B3.server_weighted(rows, lambda r: True, lambda r: r["x"]), (50.0, 1))

    def test_empty_denominator(self):
        self.assertEqual(B3.server_weighted([{"ip": "a"}], lambda r: False, lambda r: True), (None, 0))


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.proj = os.path.join(cls.tmp, "proj")
        shutil.copytree(os.path.join(BASE, "measurement"), os.path.join(cls.proj, "measurement"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        raw = os.path.join(cls.proj, "data", "measurement", "runs", "run_test", "raw")
        proc = os.path.join(cls.proj, "data", "measurement", "processed")
        os.makedirs(raw)
        os.makedirs(proc)
        with open(os.path.join(proc, "live_domains.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "sector", "category", "tier", "ip", "family"])
            for d, cat, tier, ip in LIVE:
                w.writerow([d, f"{cat} (x)", cat, tier, ip, "4"])
        for name, recs in (("tls.jsonl", TLS_RECS), ("http.jsonl", HTTP_RECS)):
            with open(os.path.join(raw, name), "w") as f:
                for r in recs:
                    f.write(json.dumps(r) + "\n")
        cls.p = subprocess.run([sys.executable, "measurement/phase_b_tls/b3_parse_results.py", "--run-id", "run_test"],
                               cwd=cls.proj, capture_output=True, text=True)

        def load(*parts):
            with open(os.path.join(cls.proj, *parts), newline="") as f:
                return list(csv.DictReader(f))
        if cls.p.returncode == 0:
            cls.cat = {r["group"]: r for r in load("results", "tables", "phase_b_by_category.csv")}
            cls.tier = {r["group"]: r for r in load("results", "tables", "phase_b_by_tier.csv")}
            cls.dom = {r["domain"]: r for r in load("data", "measurement", "processed", "phase_b_domains.csv")}
            cls.top = load("results", "tables", "phase_b_top_servers.csv")
            with open(os.path.join(cls.proj, "results", "tables", "phase_b_report.md")) as f:
                cls.md = f.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_0_ran(self):
        self.assertEqual(self.p.returncode, 0, self.p.stdout + self.p.stderr)

    def test_university_pq_domain_vs_server(self):
        u = self.cat["university"]
        self.assertEqual((u["domains"], u["servers"]), ("5", "2"))
        self.assertEqual((u["pq_default_n"], u["pq_default_den"], u["pq_default_dom_pct"], u["pq_default_srv_pct"]),
                         ("4", "5", "80.0", "50.0"))
        self.assertEqual((u["not_capable_dom_pct"], u["not_capable_srv_pct"]), ("20.0", "50.0"))

    def test_older_duplicate_ignored(self):
        self.assertEqual(self.dom["u5"]["pq_class"], "not_capable")

    def test_old_versions(self):
        u, g = self.cat["university"], self.cat["government"]
        self.assertEqual((u["accepts_tls_1_0_or_1_1_n"], u["accepts_tls_1_0_or_1_1_den"],
                          u["accepts_tls_1_0_or_1_1_srv_pct"]), ("1", "5", "50.0"))
        self.assertEqual((g["accepts_tls_1_0_or_1_1_n"], g["accepts_tls_1_0_or_1_1_den"]), ("0", "1"))

    def test_hsts_pending_excluded_and_bounds(self):
        u = self.cat["university"]
        self.assertEqual((u["http_pending"], u["http_ok_den"], u["hsts_den"], u["hsts_n"]), ("2", "3", "3", "1"))
        self.assertEqual((u["hsts_dom_pct"], u["hsts_srv_pct"]), ("33.3", "25.0"))
        self.assertEqual((u["hsts_dom_pct_low"], u["hsts_dom_pct_high"]), ("20.0", "60.0"))
        self.assertEqual(self.dom["u3"]["http_status"], "pending")

    def test_scanned_http_failure_is_not_pending(self):
        g = self.cat["government"]
        self.assertEqual((g["http_pending"], g["http_ok_n"], g["http_ok_den"], g["http_ok_dom_pct"]), ("0", "2", "3", "66.7"))
        self.assertEqual((g["hsts_dom_pct"], g["waf_detected_dom_pct"]), ("100.0", "50.0"))

    def test_not_scanned_tls_excluded(self):
        g = self.cat["government"]
        self.assertEqual(self.dom["g3"]["tls_status"], "not_scanned")
        self.assertEqual((g["pq_default_den"], g["pq_default_dom_pct"], g["pq_default_srv_pct"], g["pq_default_srv_den"]),
                         ("2", "50.0", "50.0", "1"))

    def test_all_row(self):
        a = self.cat["ALL"]
        self.assertEqual((a["domains"], a["servers"], a["pq_default_n"], a["pq_default_den"]), ("8", "4", "5", "7"))
        self.assertEqual((a["pq_default_dom_pct"], a["pq_default_srv_pct"]), ("71.4", "50.0"))

    def test_certificates(self):
        u = self.cat["university"]
        self.assertEqual((u["cert_trusted_n"], u["cert_trusted_den"], u["cert_expired_n"]), ("4", "5", "1"))
        self.assertEqual((u["cert_rsa_below_2048_n"], u["cert_rsa_below_2048_den"]), ("1", "1"))
        self.assertEqual(self.dom["g2"]["cert_trusted"], "")        # no cert -> blank, not False

    def test_tier_table(self):
        v = self.tier["verified"]
        self.assertEqual((v["domains"], v["pq_default_n"], v["pq_default_den"]), ("6", "5", "6"))

    def test_top_servers(self):
        self.assertEqual((self.top[0]["ip"], self.top[0]["domains"], self.top[0]["http_pending"]), ("10.0.0.1", "4", "2"))

    def test_backfill_source_carried(self):
        self.assertEqual(self.dom["u2"]["http_source"], "secondary_vantage")
        self.assertEqual(self.dom["u1"]["http_source"], "primary")

    def test_notes_and_report(self):
        out = self.p.stdout
        self.assertIn("1 live domains have no TLS record", out)
        self.assertIn("2 live domains have no HTTP record yet", out)
        self.assertIn("tls=1, http=0", out)                          # one duplicate resolved
        self.assertIn("tls=1, http=0", out.split("outside the live set")[1])
        self.assertIn("| university | 5 | 2 |", self.md)
        self.assertIn("1/3", self.md)                                # small group -> k/n, not %
        self.assertIn("| pq_default | 0 | 4 | 1 |", self.md)          # crosstab: g1 inconclusive


class TestServiceHostnameFlag(unittest.TestCase):
    def test_first_label_only_and_exact(self):
        f = B3.is_service_hostname
        for d in ("cpanel.x.ac.bd", "WEBMAIL.x.gov.bd", "mail.y.gov.bd", "autodiscover.z.edu.bd", "webdisk.a.b.ac.bd"):
            self.assertTrue(f(d), d)
        for d in ("www.x.ac.bd", "x.ac.bd", "mailbox.x.ac.bd", "cpanel2.x.ac.bd", "admission.mail.x.ac.bd", "gmail.com.bd"):
            self.assertFalse(f(d), d)


class TestServiceExclusionEndToEnd(unittest.TestCase):
    """
    10.1.0.1: www.x.ac.bd (pq_default, HSTS), cpanel.x.ac.bd + webmail.x.ac.bd (not_capable, no HSTS)
    10.1.0.2: y.gov.bd (pq_default, HSTS), mail.y.gov.bd (pq_default, no HSTS)
    With everything:        PQ default 3/5 = 60.0% per domain; per server (1/3 + 2/2)/2 = 66.7%
    Without the 3 service:  PQ default 2/2 = 100.0% per domain and per server; HSTS 2/2 = 100.0%
    """
    LIVE = [("www.x.ac.bd", "university", "10.1.0.1"), ("cpanel.x.ac.bd", "university", "10.1.0.1"),
            ("webmail.x.ac.bd", "university", "10.1.0.1"), ("y.gov.bd", "government", "10.1.0.2"),
            ("mail.y.gov.bd", "government", "10.1.0.2")]
    PQ = {"www.x.ac.bd": "pq_default", "cpanel.x.ac.bd": "not_capable", "webmail.x.ac.bd": "not_capable",
          "y.gov.bd": "pq_default", "mail.y.gov.bd": "pq_default"}
    HSTS = {"www.x.ac.bd": True, "y.gov.bd": True}

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.proj = os.path.join(cls.tmp, "proj")
        shutil.copytree(os.path.join(BASE, "measurement"), os.path.join(cls.proj, "measurement"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        raw = os.path.join(cls.proj, "data", "measurement", "runs", "run_s", "raw")
        proc = os.path.join(cls.proj, "data", "measurement", "processed")
        os.makedirs(raw)
        os.makedirs(proc)
        with open(os.path.join(proc, "live_domains.csv"), "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["domain", "sector", "category", "tier", "ip", "family"])
            for d, cat, ip in cls.LIVE:
                w.writerow([d, cat, cat, "verified", ip, "4"])
        with open(os.path.join(raw, "tls.jsonl"), "w") as f:
            for d, _, ip in cls.LIVE:
                f.write(json.dumps(tls(d, ip, cls.PQ[d], False, EC_OK)) + "\n")
        with open(os.path.join(raw, "http.jsonl"), "w") as f:
            for d, _, ip in cls.LIVE:
                f.write(json.dumps(http(d, ip, hsts=cls.HSTS.get(d, False))) + "\n")
        cls.p = subprocess.run([sys.executable, "measurement/phase_b_tls/b3_parse_results.py", "--run-id", "run_s"],
                               cwd=cls.proj, capture_output=True, text=True)

        def load(name):
            with open(os.path.join(cls.proj, "results", "tables", name), newline="") as f:
                return {r["group"]: r for r in csv.DictReader(f)}
        if cls.p.returncode == 0:
            cls.full, cls.excl = load("phase_b_by_category.csv"), load("phase_b_by_category_excl_service.csv")
            cls.tier_x = load("phase_b_by_tier_excl_service.csv")
            with open(os.path.join(cls.proj, "data", "measurement", "processed", "phase_b_domains.csv"), newline="") as f:
                cls.dom = {r["domain"]: r for r in csv.DictReader(f)}
            with open(os.path.join(cls.proj, "results", "tables", "phase_b_report.md")) as f:
                cls.md = f.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_0_ran(self):
        self.assertEqual(self.p.returncode, 0, self.p.stdout + self.p.stderr)

    def test_flag_column(self):
        self.assertEqual({d: r["is_service_hostname"] for d, r in self.dom.items()},
                         {"www.x.ac.bd": "False", "cpanel.x.ac.bd": "True", "webmail.x.ac.bd": "True",
                          "y.gov.bd": "False", "mail.y.gov.bd": "True"})

    def test_full_table_keeps_everything(self):
        a = self.full["ALL"]
        self.assertEqual((a["domains"], a["pq_default_dom_pct"], a["pq_default_srv_pct"]), ("5", "60.0", "66.7"))

    def test_excluded_table(self):
        a = self.excl["ALL"]
        self.assertEqual((a["domains"], a["servers"], a["pq_default_dom_pct"], a["pq_default_srv_pct"], a["hsts_dom_pct"]),
                         ("2", "2", "100.0", "100.0", "100.0"))
        self.assertEqual(self.excl["university"]["domains"], "1")
        self.assertEqual(self.tier_x["ALL"]["domains"], "2")

    def test_report_and_console(self):
        self.assertIn("## Sensitivity: excluding 3 auto-created service hostnames", self.md)
        self.assertIn("Excluding 3 service hostnames (2 domains, 2 servers)", self.p.stdout)
        self.assertIn("pq_default               dom 60.0% -> 100.0%", self.p.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)  