#!/usr/bin/env python3
"""
Shared I/O helpers for the measurement pipeline: config, run folders, and
resumable append-only JSONL output.

Raw scan output is ALWAYS append-only JSONL (one JSON object per line), so a
crashed or interrupted scan can be re-run and will skip domains already done.
"""

import copy
import datetime
import json
import os
import sys
import threading

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MEAS_DIR = os.path.join(BASE, "data", "measurement")
RUNS_DIR = os.path.join(MEAS_DIR, "runs")
PROCESSED_DIR = os.path.join(MEAS_DIR, "processed")
INPUT_DIR = os.path.join(MEAS_DIR, "input")
CONFIG_PATH = os.path.join(BASE, "measurement", "config.yaml")

DEFAULTS = {
    "vantage_point": "",
    "dns": {"nameservers": ["1.1.1.1", "8.8.8.8"], "timeout_s": 3.0, "lifetime_s": 8.0,
            "retries": 2, "workers": 200, "max_qps": 100, "query_dnssec": True},
    "port443": {"connect_timeout_s": 5.0, "workers": 100, "max_ips_tried": 3,
                "try_ipv6": True, "max_per_ip": 4, "max_cps": 100},
    "tls": {"timeout_s": 10.0, "workers": 50, "max_cps": 30, "max_per_ip": 3,
            "control_hosts": ["pq.cloudflareresearch.com", "www.cloudflare.com"]},
    "legacy": {"openssl_path": "tools/legacy_openssl/bin/openssl", "timeout_s": 10.0, "workers": 30,
               "max_cps": 10, "per_ip_interval_s": 1.5, "breaker_after": 5},
    "smtp": {"port": 25, "timeout_s": 10.0, "workers": 20, "max_cps": 8, "max_per_ip": 1,
             "ehlo_name": "FILL-IN before the real run: a real, resolvable hostname that identifies the "
                         "study, e.g. 'md-sakib-rahman.github.io' -- never a bare IP address",
             "control_host": "smtp.gmail.com"},
    "http": {"timeout_s": 10.0, "workers": 80, "max_cps": 40, "max_per_ip": 4,
             "max_header_bytes": 65536,
             "user_agent": "FILL-IN before the real run: identify the study + a contact URL/email, "
                           "e.g. 'bd-tls-pqc-study/1.0 (+https://example.edu/~you/study; you@example.edu)'",
             "control_hosts": ["www.cloudflare.com"]},
}


def load_config(path=None):
    cfg = copy.deepcopy(DEFAULTS)
    path = path or CONFIG_PATH
    if os.path.exists(path):
        try:
            import yaml
        except ImportError:
            sys.exit("ERROR: PyYAML is required to read config.yaml (pip install pyyaml)")
        with open(path, encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
        for key, val in user.items():
            if isinstance(val, dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(val)
            else:
                cfg[key] = val
    return cfg


def resolve_run_dir(run_id=None, create=False):
    """Explicit run id -> that folder. No run id -> newest existing run folder."""
    if run_id:
        run_dir = os.path.join(RUNS_DIR, run_id)
        if create:
            os.makedirs(os.path.join(run_dir, "raw"), exist_ok=True)
        elif not os.path.isdir(run_dir):
            sys.exit(f"ERROR: run folder not found: {run_dir}")
        return run_dir
    runs = sorted(d for d in os.listdir(RUNS_DIR) if os.path.isdir(os.path.join(RUNS_DIR, d))) \
        if os.path.isdir(RUNS_DIR) else []
    if not runs:
        sys.exit("ERROR: no run folders exist yet. Run a1_resolve_dns.py first.")
    return os.path.join(RUNS_DIR, runs[-1])


def read_jsonl(path):
    """Yield records; silently skip a truncated/corrupt line (e.g. crash mid-write)."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def done_keys(path, key="domain"):
    return {rec[key] for rec in read_jsonl(path) if key in rec}


class JsonlWriter:
    """Thread-safe append-only JSONL writer, flushed after every record."""

    def __init__(self, path):
        self.lock = threading.Lock()
        needs_newline = False
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "rb") as f:
                f.seek(-1, os.SEEK_END)
                needs_newline = f.read(1) != b"\n"   # previous run died mid-line
        self.f = open(path, "a", encoding="utf-8")
        if needs_newline:
            self.f.write("\n")

    def write(self, record):
        line = json.dumps(record, ensure_ascii=False)
        with self.lock:
            self.f.write(line + "\n")
            self.f.flush()

    def close(self):
        self.f.close()


def update_run_meta(run_dir, section, data):
    path = os.path.join(run_dir, "run_meta.json")
    meta = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            meta = json.load(f)
    meta[section] = data
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    return meta


def read_run_meta(run_dir):
    path = os.path.join(run_dir, "run_meta.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")