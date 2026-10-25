"""Driver: runs b2's real main() against a local HTTP-over-TLS server (port patched)."""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)

port = int(sys.argv[1])
spec = importlib.util.spec_from_file_location("b2", os.path.join(BASE, "measurement", "phase_b_tls", "b2_collect_http_headers.py"))
b2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b2)
b2.PORT = port
sys.argv = ["b2"] + sys.argv[2:]
b2.main()