"""Fake DNS resolver for tests. Mimics the parts of dnspython's Resolver that a1 uses."""
import collections
import types

import dns.exception
import dns.flags
import dns.resolver


class _Rdata:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class _Answer(list):
    def __init__(self, values, ad=False):
        super().__init__(_Rdata(v) for v in values)
        self.response = types.SimpleNamespace(flags=dns.flags.AD if ad else 0)


# rtype -> list of values | (values, ad) | "NODATA" | "NXDOMAIN" | "TIMEOUT" | "SERVFAIL" | ("FLAKY", values)
# Any rtype not listed is NODATA.
SCRIPT = {
    "a.gov.bd":     {"A": (["127.0.0.1"], True), "MX": ["10 mx.a.gov.bd."]},
    "b.ac.bd":      {"A": ["127.0.0.2"]},
    "c.gov.bd":     {"A": "NXDOMAIN"},
    "d.com.bd":     {"MX": ["10 mx.d.com.bd."]},                       # exists, no A/AAAA
    "e.com.bd":     {"A": "TIMEOUT", "AAAA": "TIMEOUT"},
    "f.gov.bd":     {"A": ("FLAKY", ["127.0.0.1"])},                   # times out once, then answers
    "dbbl.com.bd":  {"A": ["127.0.0.1"], "DS": ["12345 13 2 ABCD"], "DNSKEY": ["257 3 13 KEY"]},
    "h.com.bd":     {"A": "SERVFAIL"},
}


class FakeResolver:
    def __init__(self, script=SCRIPT):
        self.script = script
        self.calls = collections.Counter()

    def resolve(self, name, rdtype, raise_on_no_answer=True):
        self.calls[(name, rdtype)] += 1
        entry = self.script.get(name, {}).get(rdtype, "NODATA")
        if isinstance(entry, tuple) and entry[0] == "FLAKY":
            if self.calls[(name, rdtype)] == 1:
                raise dns.exception.Timeout()
            return _Answer(entry[1])
        if isinstance(entry, tuple):
            return _Answer(entry[0], ad=entry[1])
        if isinstance(entry, list):
            return _Answer(entry)
        if entry == "NXDOMAIN":
            raise dns.resolver.NXDOMAIN()
        if entry == "NODATA":
            raise dns.resolver.NoAnswer()
        if entry == "TIMEOUT":
            raise dns.exception.Timeout()
        if entry == "SERVFAIL":
            raise dns.resolver.NoNameservers()
        raise AssertionError(f"bad script entry {entry!r}")
