#!/usr/bin/env python3
"""
scanner_api.py — API-focused security checks (OWASP API Security Top 10).

Complements the web scanner with API-specific, SAFE checks:
  - reachable-without-auth probe (missing authentication)
  - CORS misconfiguration (reflected origin / wildcard+credentials)
  - dangerous HTTP methods (OPTIONS/Allow advertises PUT/DELETE/TRACE)
  - GraphQL introspection enabled
  - exposed API docs (swagger/openapi)
Plus it runs the standard web built-ins (headers/cookies) via the web scanner.

All checks are non-destructive: benign GET/OPTIONS + one benign GraphQL
introspection query. No mutations, no fuzzing, no exploitation.
"""

from __future__ import annotations

import json
import os
from urllib.parse import urljoin, urlparse

from common import banner, err, finding, info, ok, warn

try:
    from common import http_get
except Exception:  # pragma: no cover
    http_get = None

try:
    import scanner_web
except Exception:
    scanner_web = None

COMMON_DOC_PATHS = ("/swagger.json", "/openapi.json", "/swagger-ui.html",
                    "/api-docs", "/v2/api-docs", "/graphql", "/api/swagger.json")


def _req(url, method="GET", timeout=12):
    """Minimal request helper (urllib) that supports arbitrary methods."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": "vulnscan-api/1.0",
                                          "Origin": "https://evil.example"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(20000).decode("utf-8", "replace")
            return r.status, {k.lower(): v for k, v in r.headers.items()}, body
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, ""
    except Exception:
        return None, {}, ""


def _check_cors(url, out):
    status, headers, _ = _req(url)
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "https://evil.example" and acac.lower() == "true":
        out.append(finding("api.cors", f"Reflects arbitrary Origin with credentials at {url}"))
    elif acao == "*" and acac.lower() == "true":
        out.append(finding("api.cors", f"Wildcard ACAO with credentials at {url}"))


def _check_methods(url, out):
    status, headers, _ = _req(url, method="OPTIONS")
    allow = headers.get("allow", "") or headers.get("access-control-allow-methods", "")
    dangerous = [m for m in ("PUT", "DELETE", "TRACE", "PATCH") if m in allow.upper()]
    if dangerous:
        out.append(finding("api.verb", f"{url} advertises {', '.join(dangerous)} (Allow: {allow})"))


def _check_graphql(base, out):
    gql = urljoin(base, "/graphql")
    # benign introspection query — read-only, no mutation
    import urllib.request
    data = json.dumps({"query": "{__schema{queryType{name}}}"}).encode()
    req = urllib.request.Request(gql, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "vulnscan-api/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            body = r.read(20000).decode("utf-8", "replace")
        if "__schema" in body or "queryType" in body:
            out.append(finding("api.graphql_introspection", f"Introspection answered at {gql}"))
    except Exception:
        pass


def _check_docs(base, out):
    for p in COMMON_DOC_PATHS:
        url = urljoin(base, p)
        status, headers, body = _req(url)
        if status == 200 and any(k in body.lower() for k in ("swagger", "openapi", "\"paths\"", "__schema")):
            out.append(finding("api.docs_exposed", f"API spec/docs exposed at {url}"))
            break


def _check_no_auth(base, out):
    # if a likely API root returns 200 with JSON and no auth header was sent, flag for review
    status, headers, body = _req(base)
    ct = headers.get("content-type", "")
    if status == 200 and "json" in ct and len(body) > 2:
        out.append(finding("api.no_auth",
                           f"{base} returns JSON without authentication (verify authZ per object)",
                           severity_override="medium"))


def scan(target: str, outdir: str, skip: set) -> dict:
    result = {"profile": "api", "target": target, "findings": [], "tools": []}
    base = target if target.startswith("http") else f"https://{target}"

    banner(f"API — OWASP API Security checks on {base}")
    if http_get is None:
        warn("no HTTP client available")
        return result

    # reuse web built-ins (headers/cookies/reflection) via the web scanner
    if scanner_web is not None:
        try:
            web = scanner_web.scan(base, outdir, skip | {"nmap", "nikto", "nuclei", "sqlmap",
                                                          "whatweb", "testssl"})
            result["findings"] += web.get("findings", [])
            result["tools"] += web.get("tools", [])
        except Exception as e:
            warn(f"web built-ins failed: {e}")

    out = []
    try:
        _check_no_auth(base, out)
        _check_cors(base, out)
        _check_methods(base, out)
        _check_graphql(base, out)
        _check_docs(base, out)
        ok(f"API checks complete ({len(out)} API-specific finding(s))")
    except Exception as e:
        err(f"API checks error: {e}")
    result["findings"] += out
    result["tools"].append({"tool": "api-checks", "status": "done"})
    return result
