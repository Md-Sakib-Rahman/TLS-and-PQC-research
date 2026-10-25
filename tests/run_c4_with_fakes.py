"""
Driver: runs c4's real main() but redirects each MX host's connection to a local fake server port
(via env C4_TEST_PORT_MX1 / C4_TEST_PORT_MX2), while DNS resolution for the *.nip.io test hostnames
happens for real (nip.io is a public wildcard-DNS service that resolves <ip-with-dashes>.nip.io to
that IP -- here always 127.0.0.1, so the SMTP connection itself is pure loopback either way).
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)

PORT_BY_HOST = {
    "127-0-0-1-mx1.nip.io": int(os.environ.get("C4_TEST_PORT_MX1", "0")),
    "127-0-0-1-mx2.nip.io": int(os.environ.get("C4_TEST_PORT_MX2", "0")),
}

spec = importlib.util.spec_from_file_location("c4", os.path.join(BASE, "measurement", "phase_c_derived", "c4_smtp_scan.py"))
c4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c4)

orig_probe = c4.S.probe_smtp


def patched_probe(host, ip, ehlo_name, port, timeout, ctx=None):
    return orig_probe(host, ip, ehlo_name, PORT_BY_HOST.get(host, port), timeout, ctx)


c4.S.probe_smtp = patched_probe
sys.argv = ["c4"] + sys.argv[1:]
c4.main()