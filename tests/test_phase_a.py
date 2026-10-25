#!/usr/bin/env python3
"""
Tests for Phase A. Synthetic data only -- no real network beyond localhost.
Run from project root:  python -m unittest tests.test_phase_a -v   (or: python tests/test_phase_a.py)
"""

import csv
import errno
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)
sys.path.insert(0, HERE)

import fakes
from measurement.common import io_utils
from measurement.common.corpus import sector_category, verification_tier
from measurement.common.net_utils import RateLimiter


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BASE, "measurement", "phase_a_liveness", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


a1, a2, a3, a4 = (load_script(n) for n in
                  ("a1_resolve_dns", "a2_check_port443", "a3_build_live_list", "a4_attrition_report"))
DNS_CFG = io_utils.DEFAULTS["dns"]
P443_CFG = dict(io_utils.DEFAULTS["port443"], connect_timeout_s=0.5)
FAST = RateLimiter(0)


class TestCorpusLabels(unittest.TestCase):
    def test_categories_and_tiers(self):
        cases = {
            "university (institution-verified)": ("university", "verified"),
            "government (heuristic -- not verified)": ("government", "unverified"),
            "commercial (heuristic -- review manually)": ("commercial", "unverified"),
            "banking (source-verified)": ("banking", "verified"),
            "banking (keyword match -- rejected, false positive)": ("banking", "rejected"),
            "banking (keyword match -- not yet individually verified)": ("banking", "unverified"),
            "unclassified": ("unclassified", "unverified"),
            "defence (heuristic)": ("defence", "unverified"),
        }
        for sector, (cat, tier) in cases.items():
            self.assertEqual((sector_category(sector), verification_tier(sector)), (cat, tier), sector)


class TestJsonl(unittest.TestCase):
    def test_truncated_last_line_is_skipped_and_writer_recovers(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.jsonl")
            with open(p, "w") as f:
                f.write('{"domain": "ok1"}\n{"domain": "trunc", "A": {')      # crash mid-write, no newline
            w = io_utils.JsonlWriter(p)
            w.write({"domain": "ok2"})
            w.close()
            self.assertEqual({r["domain"] for r in io_utils.read_jsonl(p)}, {"ok1", "ok2"})


class TestA1Resolve(unittest.TestCase):
    def setUp(self):
        a1._local.__dict__.clear()

    def rec(self, name):
        return a1.resolve_domain(name, DNS_CFG, FAST, resolver_factory=lambda c: fakes.FakeResolver())

    def test_live_domain_with_ad_flag_and_mx(self):
        r = self.rec("a.gov.bd")
        self.assertTrue(r["resolves"])
        self.assertEqual(r["A"], {"status": "ok", "values": ["127.0.0.1"], "ad": True})
        self.assertEqual(r["MX"]["status"], "ok")
        self.assertEqual(r["DS"]["status"], "nodata")

    def test_nxdomain_skips_other_queries(self):
        r = self.rec("c.gov.bd")
        self.assertFalse(r["resolves"])
        self.assertTrue(all(r[t]["status"] == "nxdomain" for t in ("A", "AAAA", "MX", "DS", "DNSKEY")))

    def test_nodata_is_not_nxdomain(self):
        r = self.rec("d.com.bd")
        self.assertEqual((r["A"]["status"], r["AAAA"]["status"], r["MX"]["status"]), ("nodata", "nodata", "ok"))

    def test_timeout_exhausts_retries(self):
        res = fakes.FakeResolver()
        r = a1.resolve_domain("e.com.bd", DNS_CFG, FAST, resolver_factory=lambda c: res)
        self.assertEqual(r["A"]["status"], "timeout")
        self.assertEqual(res.calls[("e.com.bd", "A")], DNS_CFG["retries"] + 1)
        self.assertEqual(res.calls[("e.com.bd", "AAAA")], 1)               # single attempt after A failed
        self.assertTrue(all(r[t]["status"] == "skipped" for t in ("MX", "DS", "DNSKEY")))

    def test_retry_recovers_flaky(self):
        r = self.rec("f.gov.bd")
        self.assertEqual(r["A"]["status"], "ok")

    def test_servfail_recorded_separately(self):
        self.assertEqual(self.rec("h.com.bd")["A"]["status"], "servfail")

    def test_servfail_not_retried_and_remaining_queries_skipped(self):
        res = fakes.FakeResolver()
        r = a1.resolve_domain("h.com.bd", DNS_CFG, FAST, resolver_factory=lambda c: res)
        self.assertEqual(res.calls[("h.com.bd", "A")], 1)
        self.assertEqual(res.calls[("h.com.bd", "AAAA")], 1)
        for t in ("MX", "DS", "DNSKEY"):
            self.assertEqual(r[t]["status"], "skipped")
            self.assertEqual(res.calls[("h.com.bd", t)], 0)

    def test_aaaa_can_still_rescue_a_failed_a_lookup(self):
        script = {"x.bd": {"A": "TIMEOUT", "AAAA": ["2001:db8::1"]}}
        r = a1.resolve_domain("x.bd", DNS_CFG, FAST, resolver_factory=lambda c: fakes.FakeResolver(script))
        self.assertTrue(r["resolves"])

    def test_dnssec_records_and_toggle(self):
        r = self.rec("dbbl.com.bd")
        self.assertEqual((r["DS"]["status"], r["DNSKEY"]["status"]), ("ok", "ok"))
        cfg = dict(DNS_CFG, query_dnssec=False)
        a1._local.__dict__.clear()
        r2 = a1.resolve_domain("dbbl.com.bd", cfg, FAST, resolver_factory=lambda c: fakes.FakeResolver())
        self.assertNotIn("DS", r2)


class TestA2Port443(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = socket.socket()
        cls.srv.bind(("127.0.0.1", 0))
        cls.srv.listen(10)
        cls.open_port = cls.srv.getsockname()[1]
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        cls.closed_port = s.getsockname()[1]
        s.close()                                     # nothing listens here -> connection refused

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def dns(self, *ips):
        return {"domain": "t.bd", "A": {"status": "ok", "values": list(ips)}}

    def test_open(self):
        r = a2.check_domain(self.dns("127.0.0.1"), P443_CFG, FAST, port=self.open_port)
        self.assertEqual((r["port443"], r["ip"], r["family"]), ("open", "127.0.0.1", 4))

    def test_closed_when_all_refused(self):
        r = a2.check_domain(self.dns("127.0.0.1"), P443_CFG, FAST, port=self.closed_port)
        self.assertEqual(r["port443"], "closed")
        self.assertEqual(r["attempts"][0]["result"], "refused")

    def patched(self, table):
        """Mock the socket layer: table maps ip -> result string (no real network needed)."""
        return mock.patch.object(a2, "try_connect", side_effect=lambda ip, fam, port, t: (table[ip], None))

    def test_no_response_for_timeouts(self):
        with self.patched({"10.0.0.1": "timeout"}):
            r = a2.check_domain(self.dns("10.0.0.1"), P443_CFG, FAST)
        self.assertEqual(r["port443"], "no_response")

    def test_falls_through_to_second_ip_and_respects_cap(self):
        table = {"10.0.0.1": "timeout", "10.0.0.2": "open"}
        with self.patched(table):
            r = a2.check_domain(self.dns("10.0.0.1", "10.0.0.2"), P443_CFG, FAST)
            self.assertEqual((r["port443"], r["ip"]), ("open", "10.0.0.2"))
            r = a2.check_domain(self.dns("10.0.0.1", "10.0.0.2"), dict(P443_CFG, max_ips_tried=1), FAST)
        self.assertEqual(r["port443"], "no_response")

    def test_mixed_refused_and_timeout_is_not_closed(self):
        with self.patched({"10.0.0.1": "refused", "10.0.0.2": "timeout"}):
            r = a2.check_domain(self.dns("10.0.0.1", "10.0.0.2"), P443_CFG, FAST)
        self.assertEqual(r["port443"], "no_response")

    def test_error_classification(self):
        class FakeSock:
            exc = None
            def __init__(self, *a): pass
            def settimeout(self, t): pass
            def connect(self, addr): raise FakeSock.exc
            def close(self): pass
        cases = [(TimeoutError(), "timeout"), (ConnectionRefusedError(), "refused"),
                 (OSError(errno.ENETUNREACH, "x"), "unreachable"), (OSError(errno.EHOSTUNREACH, "x"), "unreachable"),
                 (OSError(errno.EPERM, "x"), "error:EPERM")]
        for exc, expected in cases:
            FakeSock.exc = exc
            with mock.patch.object(a2.socket, "socket", FakeSock):
                self.assertEqual(a2.try_connect("10.0.0.1", 4, 443, 0.1)[0], expected, repr(exc))

    def test_control_check_detects_intercepting_network(self):
        with self.patched({ip: "timeout" for ip in a2.CONTROL_IPS}):
            self.assertTrue(a2.control_check(0.1)[1])
        with self.patched({a2.CONTROL_IPS[0]: "refused", a2.CONTROL_IPS[1]: "open"}):
            self.assertFalse(a2.control_check(0.1)[1])

    def test_shared_ip_is_probed_once(self):
        calls = []
        def fake(ip, fam, port, t):
            calls.append(ip)
            return "open", 5
        with mock.patch.object(a2, "try_connect", side_effect=fake):
            cache = a2.ProbeCache()
            r1 = a2.check_domain(self.dns("10.0.0.1"), P443_CFG, FAST, cache=cache)
            r2 = a2.check_domain(self.dns("10.0.0.1"), P443_CFG, FAST, cache=cache)
            self.assertEqual(calls, ["10.0.0.1"])                          # one connect for two domains
            self.assertEqual((r1["port443"], r2["port443"], r2["ip"]), ("open", "open", "10.0.0.1"))
            a2.check_domain(self.dns("10.0.0.1"), P443_CFG, FAST)          # no shared cache -> probes again
            self.assertEqual(len(calls), 2)

    def test_shared_ip_probed_once_under_concurrency(self):
        import time
        from concurrent.futures import ThreadPoolExecutor
        calls = []
        def slow(ip, fam, port, t):
            calls.append(ip)
            time.sleep(0.05)
            return "timeout", None
        with mock.patch.object(a2, "try_connect", side_effect=slow):
            cache = a2.ProbeCache()
            with ThreadPoolExecutor(20) as pool:
                results = list(pool.map(lambda _: a2.check_domain(self.dns("10.0.0.9"), P443_CFG, FAST, cache=cache), range(20)))
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(r["port443"] == "no_response" for r in results))

    def test_cache_is_keyed_by_port(self):
        with mock.patch.object(a2, "try_connect", side_effect=lambda ip, f, port, t: ("open" if port == 443 else "refused", 1)) as m:
            cache = a2.ProbeCache()
            a = a2.check_domain(self.dns("10.0.0.1"), P443_CFG, FAST, port=443, cache=cache)
            b = a2.check_domain(self.dns("10.0.0.1"), P443_CFG, FAST, port=8443, cache=cache)
        self.assertEqual((a["port443"], b["port443"]), ("open", "closed"))

    def test_ipv4_before_ipv6_and_ipv6_toggle(self):
        d = {"domain": "t.bd", "A": {"status": "ok", "values": ["10.0.0.1"]}, "AAAA": {"status": "ok", "values": ["::1"]}}
        self.assertEqual(a2.candidate_ips(d, P443_CFG), [("10.0.0.1", 4), ("::1", 6)])
        self.assertEqual(a2.candidate_ips(d, dict(P443_CFG, try_ipv6=False)), [("10.0.0.1", 4)])


class TestA3A4Logic(unittest.TestCase):
    def test_dns_status_buckets(self):
        mk = lambda a, aaaa, res=False: {"resolves": res, "A": {"status": a}, "AAAA": {"status": aaaa}}
        self.assertEqual(a3.dns_status(mk("ok", "nodata", True)), "resolves")
        self.assertEqual(a3.dns_status(mk("nxdomain", "nxdomain")), "nxdomain")
        self.assertEqual(a3.dns_status(mk("nodata", "nodata")), "no_address")
        self.assertEqual(a3.dns_status(mk("timeout", "nodata")), "inconclusive")
        self.assertEqual(a3.dns_status(mk("nodata", "servfail")), "inconclusive")

    def test_not_scanned_rows_excluded_from_denominator(self):
        rows = [{"category": "x", "dns_status": s, "port443": p}
                for s, p in [("resolves", "open"), ("nxdomain", "n/a"), ("not_scanned", "n/a"), ("not_scanned", "n/a")]]
        r = a4.summary_row("x", rows)
        self.assertEqual((r["corpus_total"], r["scanned"], r["resolves_pct"], r["open_443_pct"]), (4, 2, 50.0, 50.0))


class TestEndToEnd(unittest.TestCase):
    """Copies the project into a temp folder and runs freeze -> a1 -> a2 -> a3 -> a4 as real subprocesses."""

    CORPUS = [
        ("a.gov.bd", "government (institution-verified)"),
        ("b.ac.bd", "university (institution-verified)"),
        ("c.gov.bd", "government (heuristic -- not verified)"),
        ("d.com.bd", "commercial (heuristic -- review manually)"),
        ("e.com.bd", "commercial (heuristic -- review manually)"),
        ("f.gov.bd", "government (heuristic -- not verified)"),
        ("dbbl.com.bd", "banking (source-verified)"),
        ("h.com.bd", "banking (keyword match -- rejected, false positive)"),
    ]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.proj = os.path.join(cls.tmp, "proj")
        os.makedirs(os.path.join(cls.proj, "data", "processed"))
        for sub in ("measurement", "tests"):
            shutil.copytree(os.path.join(BASE, sub), os.path.join(cls.proj, sub),
                            ignore=shutil.ignore_patterns("__pycache__"))
        cfg = os.path.join(cls.proj, "measurement", "config.yaml")
        with open(cfg) as f:
            txt = f.read().replace("max_qps: 100", "max_qps: 100000").replace("max_cps: 100", "max_cps: 100000")
        txt = txt.replace("connect_timeout_s: 5.0", "connect_timeout_s: 0.5")
        with open(cfg, "w") as f:
            f.write(txt)
        with open(os.path.join(cls.proj, "data", "processed", "domains_master.csv"), "w", newline="") as f:
            w = csv.writer(f)                                            # CRLF like the real corpus
            w.writerow(["domain", "source", "date_added", "sector", "verification_note"])
            for d, s in cls.CORPUS:
                w.writerow([d, "test", "2026-09-19", s, ""])
        cls.sh("measurement/common/corpus.py", "freeze")
        cls.sh("tests/run_with_fakes.py", "a1", "--run-id", "run_test")
        cls.sh("tests/run_with_fakes.py", "a2", "--run-id", "run_test")
        cls.sh("measurement/phase_a_liveness/a3_build_live_list.py", "--run-id", "run_test")
        cls.report = cls.sh("measurement/phase_a_liveness/a4_attrition_report.py", "--run-id", "run_test")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def sh(cls, *cmd):
        p = subprocess.run([sys.executable, *cmd], cwd=cls.proj, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"{cmd} failed:\n{p.stdout}\n{p.stderr}")
        return p.stdout

    def csv_rows(self, *parts):
        with open(os.path.join(self.proj, *parts), newline="") as f:
            return list(csv.DictReader(f))

    def test_freeze_wrote_hash(self):
        files = os.listdir(os.path.join(self.proj, "data", "measurement", "input"))
        self.assertEqual(sorted(f.split(".csv")[-1] for f in files), ["", ".sha256"])

    def test_liveness_all(self):
        rows = {r["domain"]: r for r in self.csv_rows("data", "measurement", "processed", "liveness_all.csv")}
        self.assertEqual(len(rows), 8)
        expect = {"a.gov.bd": ("resolves", "open"), "b.ac.bd": ("resolves", "closed"),
                  "c.gov.bd": ("nxdomain", "n/a"), "d.com.bd": ("no_address", "n/a"),
                  "e.com.bd": ("inconclusive", "n/a"), "f.gov.bd": ("resolves", "open"),
                  "dbbl.com.bd": ("resolves", "open"), "h.com.bd": ("inconclusive", "n/a")}
        for d, (dnss, p443) in expect.items():
            self.assertEqual((rows[d]["dns_status"], rows[d]["port443"]), (dnss, p443), d)
        self.assertEqual(rows["a.gov.bd"]["ad_validated"], "True")
        self.assertEqual(rows["dbbl.com.bd"]["ds_present"], "True")
        self.assertEqual(rows["d.com.bd"]["has_mx"], "True")

    def test_live_list_is_exactly_the_open_domains(self):
        live = {r["domain"] for r in self.csv_rows("data", "measurement", "processed", "live_domains.csv")}
        self.assertEqual(live, {"a.gov.bd", "f.gov.bd", "dbbl.com.bd"})

    def test_attrition_numbers(self):
        cat = {r["group"]: r for r in self.csv_rows("results", "tables", "phase_a_attrition_by_category.csv")}
        tier = {r["group"]: r for r in self.csv_rows("results", "tables", "phase_a_attrition_by_tier.csv")}
        g = cat["government"]
        self.assertEqual((g["corpus_total"], g["resolves"], g["open_443"], g["nxdomain"]), ("3", "2", "2", "1"))
        u = cat["university"]
        self.assertEqual((u["resolves"], u["closed"], u["open_443"]), ("1", "1", "0"))
        b = cat["banking"]
        self.assertEqual((b["corpus_total"], b["resolves"], b["open_443"], b["inconclusive"]), ("2", "1", "1", "1"))
        self.assertEqual((cat["commercial"]["no_address"], cat["commercial"]["inconclusive"]), ("1", "1"))
        v, un, rj = tier["verified"], tier["unverified"], tier["rejected"]
        self.assertEqual((v["corpus_total"], v["resolves"], v["open_443"]), ("3", "3", "2"))
        self.assertEqual((un["corpus_total"], un["resolves"], un["open_443"]), ("4", "1", "1"))
        self.assertEqual((rj["corpus_total"], rj["inconclusive"]), ("1", "1"))
        a = tier["ALL"]
        self.assertEqual((a["scanned"], a["resolves"], a["resolves_pct"], a["open_443_pct"], a["open_pct_of_resolving"]),
                         ("8", "4", "50.0", "37.5", "75.0"))
        self.assertNotIn("WARNING", self.report)

    def test_resume_does_nothing_when_complete(self):
        out = self.sh("tests/run_with_fakes.py", "a1", "--run-id", "run_test")
        self.assertIn("to do 0", out)
        out = self.sh("tests/run_with_fakes.py", "a2", "--run-id", "run_test")
        self.assertIn("to do 0", out)

    def test_run_meta_records_provenance(self):
        with open(os.path.join(self.proj, "data", "measurement", "runs", "run_test", "run_meta.json")) as f:
            meta = json.load(f)
        for key in ("input", "environment", "dns", "port443"):
            self.assertIn(key, meta)
        self.assertEqual(len(meta["input"]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)