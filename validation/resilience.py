#!/usr/bin/env python3
"""
validation/resilience.py — Availability & Resilience assessment (safe, passive).

This is NOT a DoS tool. It performs a small number of ordinary requests and
inspects RESPONSE HEADERS to reason about availability controls: rate limiting,
WAF/CDN edge protection, and obvious amplification surface. No flooding, no
load generation — that would require an explicit, bounded, authorized
load-testing opt-in which is out of scope here and disabled by default.
"""

from __future__ import annotations

try:
    from common import http_get
except Exception:  # pragma: no cover
    def http_get(url, timeout=15):
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "vulnscan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8", "replace"), None

_RATE_HEADERS = ("x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit",
                 "ratelimit-remaining", "retry-after", "x-rate-limit-limit")
_EDGE_HINTS = {
    "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare",
    "x-akamai-transformed": "Akamai", "x-amz-cf-id": "AWS CloudFront",
    "x-fastly-request-id": "Fastly", "x-served-by": "Fastly/Varnish",
    "x-azure-ref": "Azure Front Door", "x-sucuri-id": "Sucuri",
}
_WAF_SERVER_HINTS = ("cloudflare", "akamai", "awselb", "fastly", "sucuri", "imperva", "incapsula")


def assess(target: str, timeout: int = 12) -> list[dict]:
    """Return legacy-style finding dicts (converted upstream to Findings)."""
    url = target if target.startswith("http") else f"https://{target}"
    out: list[dict] = []
    try:
        status, headers, body, _ = http_get(url, timeout=timeout)
    except Exception:
        return out  # unreachable -> nothing to assert (safe)

    # rate limiting (passive)
    if not any(h in headers for h in _RATE_HEADERS):
        out.append({"id": "availability.no_rate_limit",
                    "evidence": f"no rate-limit headers on {url} (passive signal)"})

    # edge protection (WAF/CDN)
    edge = None
    for h, name in _EDGE_HINTS.items():
        if h in headers:
            edge = name
            break
    server = headers.get("server", "").lower()
    if not edge and any(w in server for w in _WAF_SERVER_HINTS):
        edge = headers.get("server")
    if not edge:
        out.append({"id": "availability.no_edge_protection",
                    "evidence": f"no CDN/WAF fingerprint in headers of {url} (passive signal)"})

    # amplification surface (very light heuristic: obviously expensive params/endpoints)
    low = (url + " " + (body[:500] if body else "")).lower()
    if any(k in low for k in ("export", "download=all", "report", "search?", "graphql")):
        out.append({"id": "availability.amplification_surface",
                    "evidence": f"potentially expensive endpoint/param near {url}"})
    return out
