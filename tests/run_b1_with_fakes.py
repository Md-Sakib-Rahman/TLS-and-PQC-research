"""Driver: runs b1's real main() against a local TLS server (port patched). Used by test_phase_b.py."""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)

port = int(sys.argv[1])
spec = importlib.util.spec_from_file_location("b1", os.path.join(BASE, "measurement", "phase_b_tls", "b1_tls_handshake_scan.py"))
b1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b1)
b1.PORT = port
sys.argv = ["b1"] + sys.argv[2:]
b1.main()