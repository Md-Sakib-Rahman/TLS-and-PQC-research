"""Driver: runs c2b's real main() with the target port patched to a local test server port."""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, BASE)

port = int(sys.argv[1])
spec = importlib.util.spec_from_file_location("c2b", os.path.join(BASE, "measurement", "phase_c_derived", "c2b_legacy_scan.py"))
c2b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c2b)
c2b.PORT = port
sys.argv = ["c2b"] + sys.argv[2:]
c2b.main()
