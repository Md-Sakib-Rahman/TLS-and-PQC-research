#!/usr/bin/env python3
"""Small network helpers shared by the measurement scripts."""

import threading
import time


class RateLimiter:
    """Global cap on operations per second, shared by all worker threads."""

    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self.lock = threading.Lock()
        self.next_time = 0.0

    def wait(self):
        if not self.interval:
            return
        with self.lock:
            now = time.monotonic()
            delay = self.next_time - now
            self.next_time = max(now, self.next_time) + self.interval
        if delay > 0:
            time.sleep(delay)


import contextlib
import threading as _threading


class Gate:
    """Per-IP semaphore + global connection-rate limit. Used around every outbound connection
    in Phase B (b1: TLS handshakes, b2: HTTP requests) so no single shared-hosting IP is hit
    with more than `max_per_ip` simultaneous connections, regardless of how many domains sit
    behind it (1,217 domains share one IP in this corpus -- see Phase A results)."""

    def __init__(self, max_per_ip, max_cps):
        self.cap, self.limiter = max_per_ip, RateLimiter(max_cps)
        self.sems, self.lock = {}, _threading.Lock()

    @contextlib.contextmanager
    def __call__(self, ip):
        with self.lock:
            sem = self.sems.setdefault(ip, _threading.Semaphore(self.cap))
        with sem:
            self.limiter.wait()
            yield