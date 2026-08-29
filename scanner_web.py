#!/usr/bin/env python3
"""
scanner_web.py — Website / web-app vulnerability scanner.

Built-in checks (no external tools):
  - security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer, Permissions)
  - cookie flags (Secure/HttpOnly/SameSite)
  - reflected-input (XSS indicator)
  - form + file-upload surface discovery
  - tech/version info leak

Wrapped external tools (auto-detected, skipped if missing):
  nmap, whatweb, testssl.sh, nikto, nuclei (CVE templates), sqlmap (detection only)

All findings are emitted via common.finding(kb_id, evidence) so each carries a
description, attack scenario, and patch from the knowledge base.
"""

from __future__ import annotations

import os
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from common import banner, err, finding, have, http_get, info, ok, run, warn

REQUIRED_HEADERS = {
    "content-security-policy": "web.header.csp",
    "strict-transport-security": "web.header.hsts",
    "x-frame-options": "web.header.xfo",
    "x-content-type-options": "web.header.nosniff",
    "referrer-policy": "web.header.referrer",
    "permissions-policy": "web.header.permissions",
}


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": a.get("method", "get"), "inputs": []}
        elif tag == "input" and self._cur is not None:
            self._cur["inputs"].append({"name": a.get("name", ""), "type": a.get("type", "text")})

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _builtin_checks(url: str) -> list[dict]:
    out: list[dict] = []
    try:
        status, headers, body, cookies = http_get(url)
        ok(f"fetched {url} (HTTP {status})")
    except Exception as e:
        err(f"could not fetch target: {e}")
        return out

    # Headers
    for h, fid in REQUIRED_HEADERS.items():
        if h not in headers:
            out.append(finding(fid, f"Response is missing '{h}' header."))
        else:
            ok(f"header present: {h}")

    # Info leak
    for leak in ("server", "x-powered-by", "x-aspnet-version"):
        if leak in headers:
            out.append(finding("web.infoleak", f"{leak}: {headers[leak]}"))

    # Cookies
    raw = []
    if cookies is not None:
        for c in cookies:
            raw.append((c.name, c.secure, bool(c._rest.get("HttpOnly") or c._rest.get("httponly")),
                        c._rest.get("SameSite") or c._rest.get("samesite")))
    else:
        for chunk in headers.get("set-cookie", "").split("\n"):
            if chunk.strip():
                low = chunk.lower()
                raw.append((chunk.split("=", 1)[0].strip(), "secure" in low, "httponly" in low, "samesite" in low))
    for name, secure, httponly, samesite in raw:
        missing = [x for x, present in
                   (("Secure", secure), ("HttpOnly", httponly), ("SameSite", samesite)) if not present]
        if missing:
            out.append(finding("web.cookie.flags", f"Cookie '{name}' missing: {', '.join(missing)}"))
        else:
            ok(f"cookie '{name}' fully hardened")
    if not raw:
        info("no cookies on landing page")

    # Forms + file upload
    p = _FormParser()
    try:
        p.feed(body)
    except Exception:
        pass
    for f in p.forms:
        action = urljoin(url, f["action"])
        if any(i["type"] == "file" for i in f["inputs"]):
            out.append(finding("web.fileupload", f"File-upload form -> {action}"))
        else:
            fields = [i["name"] for i in f["inputs"] if i["name"]]
            info(f"form ({f['method'].upper()}) -> {action} fields={fields}")

    # Reflected-input probe (non-destructive XSS indicator)
    marker = "vlnscn7391xZ"
    parsed = urlparse(url)
    probes = [url + f"&q={marker}"] if parsed.query else []
    probes.append(urljoin(url, f"?q={marker}"))
    for u in probes:
        try:
            _, _, rb, _ = http_get(u)
        except Exception:
            continue
        if marker in rb:
            out.append(finding("web.xss.reflected", f"Input reflected unescaped at {u}"))
            break
    return out


def _tool(name: str, args: list[str], outdir: str, outfile: str, timeout: int,
          fid: str | None, hint: str = "") -> tuple[dict, list[dict]]:
    """Run an external tool; return (tool_status, findings-from-output)."""
    if not have(name if name != "testssl" else ("testssl.sh" if have("testssl.sh") else "testssl")):
        return {"tool": name, "status": "skipped", "reason": f"not installed{(' — ' + hint) if hint else ''}"}, []
    rc, out = run(args, timeout=timeout)
    path = os.path.join(outdir, outfile)
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(out)
    findings: list[dict] = []
    # Lightweight signal extraction so tool hits appear in the unified report.
    low = out.lower()
    if fid == "web.sqli" and ("is vulnerable" in low or "injectable" in low or "parameter" in low and "injectable" in low):
        findings.append(finding("web.sqli", f"sqlmap indicated injectable parameter (see {outfile})"))
    if name == "nuclei":
        for line in out.splitlines():
            if line.strip().startswith("[") and ("cve" in line.lower() or "critical" in line.lower() or "high" in line.lower()):
                findings.append(finding("web.cve", line.strip()[:200]))
    if name == "testssl" and ("sslv3" in low or "tls 1.0" in low and "offered" in low or "expired" in low):
        findings.append(finding("web.tls.weak", f"testssl flagged weak protocol/cert (see {outfile})"))
    return {"tool": name, "status": "done" if rc in (0, 1) else f"exit {rc}", "output": path}, findings


def scan(url: str, outdir: str, skip: set[str]) -> dict:
    host = urlparse(url).hostname or url
    result = {"profile": "web", "target": url, "findings": [], "tools": []}

    banner("WEB — built-in checks (headers/cookies/forms/reflection/info-leak)")
    result["findings"] += _builtin_checks(url)

    stages = [
        ("nmap", ["nmap", "-sV", "-Pn", "--top-ports", "1000", host], "nmap.txt", 1200, None, "apt/dnf install nmap"),
        ("whatweb", ["whatweb", "-a", "3", url], "whatweb.txt", 300, None, ""),
        ("testssl", ["testssl.sh" if have("testssl.sh") else "testssl", "--quiet", "--color", "0", host],
         "testssl.txt", 1200, "web.tls.weak", "github.com/drwetter/testssl.sh"),
        ("nikto", ["nikto", "-h", url, "-maxtime", "600s"], "nikto.txt", 900, None, ""),
        ("nuclei", ["nuclei", "-u", url, "-etags", "dos,intrusive,fuzz", "-silent"], "nuclei.txt", 1800,
         None, "github.com/projectdiscovery/nuclei"),
        ("sqlmap", ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1", "--crawl=1", "--smart",
                    "--flush-session"], "sqlmap.txt", 1800, "web.sqli", ""),
    ]
    for name, args, outfile, timeout, fid, hint in stages:
        banner(f"WEB — tool: {name}")
        if name in skip:
            warn(f"skipped {name} (--skip)")
            result["tools"].append({"tool": name, "status": "skipped", "reason": "--skip"})
            continue
        status, fnds = _tool(name, args, outdir, outfile, timeout, fid, hint)
        result["tools"].append(status)
        result["findings"] += fnds
        if status["status"].startswith("skip"):
            warn(f"{name}: {status['reason']}")
        else:
            ok(f"{name}: {status['status']} -> {status.get('output')}")
    return result
