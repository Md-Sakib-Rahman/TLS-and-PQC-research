"""Driver: runs a1 or a2's real main() but with fake DNS / a local listener. Used by test_phase_a.py."""
import importlib.util
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)
sys.path.insert(0, HERE)
import fakes


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BASE, "measurement", "phase_a_liveness", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


which = sys.argv[1]
sys.argv = [which] + sys.argv[2:]
if which == "a1":
    m = load("a1_resolve_dns")
    m.make_resolver = lambda cfg: fakes.FakeResolver()
    m.main()
elif which == "a2":
    m = load("a2_check_port443")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(50)                      # kernel completes handshakes; no accept() needed
    port = srv.getsockname()[1]
    orig = m.check_domain
    m.check_domain = lambda r, c, l, **kw: orig(r, c, l, port=port, **kw)
    sys.argv.append("--skip-control")   # localhost-only test
    m.main()