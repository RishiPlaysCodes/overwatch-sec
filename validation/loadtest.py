#!/usr/bin/env python3
"""
validation/loadtest.py — BOUNDED, authorized availability load-test (opt-in only).

This is explicitly NOT a DoS/flooding tool. It is a tiny, hard-capped, rate-limited,
time-limited, abortable probe used to observe whether an authorized target applies
throttling under mild concurrent load. It refuses to run unless ALL of these hold:

  * the policy authorization is 'lab' (a system you fully own), AND
  * the policy explicitly enables dos (dos.enabled: true), AND
  * the caller passes opt_in=True (from an explicit --load-test flag).

Hard safety caps (cannot be exceeded regardless of input):
  MAX_REQUESTS = 50, MAX_CONCURRENCY = 5, MAX_SECONDS = 10, MAX_RPS ≈ 10.

Anything above a gentle probe is intentionally impossible here.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from common import finding, info, warn

try:
    from common import http_get
except Exception:  # pragma: no cover
    def http_get(url, timeout=10):
        import urllib.request
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, "", None

# absolute, non-overridable ceilings
MAX_REQUESTS = 50
MAX_CONCURRENCY = 5
MAX_SECONDS = 10
_MIN_INTERVAL = 0.1   # ~10 rps ceiling


def allowed(policy, opt_in: bool) -> tuple[bool, str]:
    if not opt_in:
        return False, "load test not requested (use --load-test on a lab you own)"
    if getattr(policy, "authorization", "") != "lab":
        return False, "load test requires a LAB authorization policy (a system you fully own)"
    if not getattr(policy, "dos", False):
        return False, "load test requires dos.enabled: true in the lab policy"
    return True, "ok"


def run(target: str, policy, opt_in: bool = False, requests_n: int = 20,
        concurrency: int = 3, seconds: int = 5) -> list[dict]:
    """Return finding dicts. Refuses unless fully authorized; always bounded."""
    ok_run, reason = allowed(policy, opt_in)
    if not ok_run:
        warn(f"availability load-test skipped: {reason}")
        return []

    url = target if target.startswith("http") else f"https://{target}"
    # clamp to hard ceilings
    n = min(int(requests_n), MAX_REQUESTS)
    c = min(int(concurrency), MAX_CONCURRENCY)
    deadline = time.time() + min(int(seconds), MAX_SECONDS)
    info(f"bounded load-test: {n} reqs, concurrency {c}, <= {MAX_SECONDS}s, abortable — LAB only")

    statuses: list[int] = []
    throttled = 0
    sent = 0

    def one(_i):
        nonlocal throttled
        if time.time() > deadline:
            return None
        try:
            st, headers, _, _ = http_get(url, timeout=5)
        except Exception:
            return None
        if st == 429 or "retry-after" in headers:
            throttled += 1
        return st

    with ThreadPoolExecutor(max_workers=c) as ex:
        futures = []
        for i in range(n):
            if time.time() > deadline:
                break
            futures.append(ex.submit(one, i))
            sent += 1
            time.sleep(_MIN_INTERVAL)   # enforce gentle rate
        for f in futures:
            r = f.result()
            if r is not None:
                statuses.append(r)

    out = []
    if sent and throttled == 0:
        out.append(finding("availability.no_rate_limit",
                           f"bounded load-test: {sent} requests, 0 throttled (no 429/Retry-After observed)"))
    else:
        info(f"throttling observed: {throttled}/{sent} responses rate-limited (good)")
    return out
