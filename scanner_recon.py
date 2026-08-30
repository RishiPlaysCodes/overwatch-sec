#!/usr/bin/env python3
"""
scanner_recon.py — Bug-bounty / red-team RECON + vulnerability-discovery pipeline.

Point it at a root domain (e.g. example.com) and it maps the whole attack
surface and finds issues, in one shot, using the best available open-source
tools. Anything not installed is skipped with a hint (install.sh sets them up).

Pipeline (each stage auto-detected; missing tools skipped):
  1. Subdomain enumeration     subfinder, assetfinder, amass (passive)
  2. Resolve + probe HTTP      dnsx, httpx  (status/title/tech/CDN)
  3. Port / service scan       naabu  (or nmap fallback)
  4. URL collection            gau, waybackurls, katana (crawl)
  5. Content discovery [deep]  ffuf / feroxbuster  (needs a wordlist; --deep)
  6. Screenshots [deep]        gowitness
  7. WAF / CMS fingerprint     wafw00f, wpscan
  8. Templated vuln scan       nuclei  (CVEs, exposures, takeovers, misconfig;
                               'dos'/'intrusive' template tags excluded)

Scope control: pass --scope <file> (one domain per line). Discovered hosts are
confined to in-scope domains — critical for bug bounty (never test out of scope).

>>> DETECTION & RECON ONLY <<<
This pipeline enumerates and DETECTS. It does NOT auto-exploit, brute-force, or
run post-exploitation. Actual exploitation must be done manually, per-target,
within the program's authorized scope. No DoS/flood tooling is included.
"""

from __future__ import annotations

import os
import re

import cve_intel
from common import banner, err, finding, have, info, ok, run, run_live, warn


def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as fh:
            return fh.read()
    except Exception:
        return ""


def _lines(path: str) -> list[str]:
    return [l.strip() for l in _read(path).splitlines() if l.strip()]


def _write_lines(path: str, items) -> None:
    with open(path, "w") as fh:
        fh.write("\n".join(sorted(set(items))) + ("\n" if items else ""))


def _load_scope(scope_file: str | None, root: str) -> list[str]:
    scope = [root.lower()]
    if scope_file and os.path.isfile(scope_file):
        for l in _lines(scope_file):
            l = l.lower().lstrip("*.").strip()
            if l:
                scope.append(l)
    return sorted(set(scope))


def _in_scope(host: str, scope: list[str]) -> bool:
    h = host.lower().strip()
    return any(h == d or h.endswith("." + d) for d in scope)


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------
def _subdomains(root: str, outdir: str, scope: list[str]) -> list[str]:
    banner("RECON — subdomain enumeration (subfinder / assetfinder / amass)")
    found: set[str] = {root}
    ran = False
    if have("subfinder"):
        ran = True
        p = os.path.join(outdir, "subfinder.txt")
        run_live(["subfinder", "-silent", "-d", root, "-o", p], timeout=600)
        found.update(_lines(p))
    if have("assetfinder"):
        ran = True
        rc, out = run(["assetfinder", "--subs-only", root], timeout=300)
        found.update([l.strip() for l in out.splitlines() if l.strip()])
    if have("amass"):
        ran = True
        p = os.path.join(outdir, "amass.txt")
        run_live(["amass", "enum", "-passive", "-d", root, "-o", p], timeout=900)
        found.update(_lines(p))
    if not ran:
        warn("no subdomain tools (subfinder/assetfinder/amass) — using root only")
    # confine to scope
    subs = sorted({s for s in found if _in_scope(s, scope)})
    dropped = len(found) - len(subs)
    _write_lines(os.path.join(outdir, "subdomains.txt"), subs)
    ok(f"{len(subs)} in-scope subdomain(s)" + (f" ({dropped} out-of-scope dropped)" if dropped else ""))
    return subs


def _probe(subs: list[str], outdir: str) -> list[str]:
    banner("RECON — resolve + HTTP probe (dnsx / httpx)")
    subs_file = os.path.join(outdir, "subdomains.txt")
    live: list[str] = []
    if have("dnsx"):
        p = os.path.join(outdir, "resolved.txt")
        run_live(["dnsx", "-silent", "-l", subs_file, "-o", p], timeout=300)
    if have("httpx"):
        p = os.path.join(outdir, "httpx.txt")
        run_live(["httpx", "-silent", "-l", subs_file, "-title", "-tech-detect",
                  "-status-code", "-o", p], timeout=600)
        for l in _lines(p):
            live.append(l.split()[0] if l else l)
        ok(f"{len(live)} live HTTP endpoint(s)")
    else:
        warn("httpx not installed — cannot probe live hosts (pip/go install httpx)")
    _write_lines(os.path.join(outdir, "live.txt"), live)
    return live


def _ports(root: str, outdir: str, deep: bool) -> None:
    banner("RECON — port / service scan (naabu / nmap)")
    subs_file = os.path.join(outdir, "subdomains.txt")
    if have("naabu"):
        p = os.path.join(outdir, "naabu.txt")
        top = "1000" if deep else "100"
        run_live(["naabu", "-silent", "-l", subs_file, "-top-ports", top, "-o", p], timeout=900)
        ok("naabu port scan complete")
    elif have("nmap"):
        p = os.path.join(outdir, "nmap-recon.txt")
        run_live(["nmap", "-sV", "-T4", "-Pn", "--open", "--top-ports", "100",
                  "--host-timeout", "8m", "-iL", subs_file, "-oN", p], timeout=1200)
        ok("nmap port scan complete")
    else:
        warn("no port scanner (naabu/nmap) — skipping port stage")


def _urls(root: str, live: list[str], outdir: str, deep: bool) -> None:
    banner("RECON — URL collection (gau / waybackurls / katana)")
    urls: set[str] = set()
    if have("gau"):
        rc, out = run(["gau", "--subs", root], timeout=600)
        urls.update([l.strip() for l in out.splitlines() if l.strip()])
    if have("waybackurls"):
        rc, out = run(["waybackurls", root], timeout=600)
        urls.update([l.strip() for l in out.splitlines() if l.strip()])
    if have("katana") and live:
        p = os.path.join(outdir, "katana.txt")
        live_file = os.path.join(outdir, "live.txt")
        depth = "3" if deep else "1"
        run_live(["katana", "-silent", "-list", live_file, "-d", depth, "-o", p], timeout=900)
        urls.update(_lines(p))
    _write_lines(os.path.join(outdir, "urls.txt"), urls)
    if urls:
        ok(f"collected {len(urls)} URL(s) -> urls.txt")
    else:
        warn("no URL collectors (gau/waybackurls/katana) — skipping")


def _content_discovery(live: list[str], outdir: str) -> None:
    banner("RECON — content discovery [deep] (ffuf / feroxbuster)")
    wordlist = next((w for w in (
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ) if os.path.isfile(w)), None)
    if not wordlist:
        warn("no wordlist found (install seclists/dirb) — skipping content discovery")
        return
    target = live[0] if live else None
    if not target:
        warn("no live host to fuzz — skipping content discovery")
        return
    if have("feroxbuster"):
        p = os.path.join(outdir, "feroxbuster.txt")
        run_live(["feroxbuster", "-u", target, "-w", wordlist, "-q", "-o", p], timeout=1200)
        ok("feroxbuster complete")
    elif have("ffuf"):
        p = os.path.join(outdir, "ffuf.txt")
        run_live(["ffuf", "-u", f"{target.rstrip('/')}/FUZZ", "-w", wordlist,
                  "-of", "csv", "-o", p], timeout=1200)
        ok("ffuf complete")
    else:
        warn("no content-discovery tool (ffuf/feroxbuster) — skipping")


def _fingerprint(root: str, live: list[str], outdir: str, result: dict) -> None:
    banner("RECON — WAF / CMS fingerprint (wafw00f / wpscan)")
    if have("wafw00f"):
        p = os.path.join(outdir, "wafw00f.txt")
        rc, out = run(["wafw00f", f"https://{root}"], timeout=180)
        with open(p, "w") as fh:
            fh.write(out)
        if "is behind" in out.lower():
            waf = re.search(r"is behind (.+)", out)
            result["findings"].append(finding("recon.waf", (waf.group(1)[:80] if waf else "WAF detected")))
    else:
        info("wafw00f not installed — skipping WAF fingerprint")
    if have("wpscan"):
        info("wpscan available — run it manually against confirmed WordPress hosts (needs API token for CVEs)")


def _nuclei(outdir: str, result: dict, deep: bool) -> None:
    banner("RECON — templated vuln scan (nuclei: CVEs / exposures / takeovers)")
    live_file = os.path.join(outdir, "live.txt")
    if not have("nuclei"):
        warn("nuclei not installed — this is the big one; install it (github.com/projectdiscovery/nuclei)")
        result["tools"].append({"tool": "nuclei", "status": "skipped", "reason": "not installed"})
        return
    if not _lines(live_file):
        warn("no live hosts for nuclei — skipping")
        return
    p = os.path.join(outdir, "nuclei.txt")
    # Exclude destructive/noisy tags. In non-deep mode limit severity to speed up.
    cmd = ["nuclei", "-silent", "-l", live_file, "-etags", "dos,intrusive,fuzz",
           "-o", p, "-stats", "-timeout", "8"]
    if not deep:
        cmd += ["-severity", "medium,high,critical"]
    run_live(cmd, timeout=2400 if deep else 1200)
    out = _read(p)
    result["tools"].append({"tool": "nuclei", "status": "done", "output": p})
    for line in out.splitlines():
        low = line.lower()
        if not line.strip():
            continue
        if "takeover" in low:
            result["findings"].append(finding("recon.subdomain_takeover", line.strip()[:180]))
        elif any(k in low for k in ("admin", "login", "panel", "dashboard")):
            result["findings"].append(finding("recon.exposed_panel", line.strip()[:180]))
        elif any(k in low for k in ("exposure", "config", "backup", "listing")):
            result["findings"].append(finding("recon.dir_listing", line.strip()[:180]))
    # CVE enrichment (CISA KEV + CVSS)
    for cve in cve_intel.extract_cves(out):
        intel = cve_intel.enrich(cve)
        fid = "network.exploit_known" if intel["kev"] else "web.cve"
        result["findings"].append(finding(fid, f"{cve_intel.describe(intel)} (nuclei)", severity_override=intel["severity"]))
    ok("nuclei scan complete")


# ---------------------------------------------------------------------------
def scan(target: str, outdir: str, skip: set[str]) -> dict:
    deep = "__deep__" in skip
    scope_file = None
    for s in skip:
        if s.startswith("scope="):
            scope_file = s.split("=", 1)[1]

    root = re.sub(r"^https?://", "", target).strip("/").split("/")[0].lower()
    result = {"profile": "recon", "target": root, "findings": [], "tools": []}

    banner(f"RECON PIPELINE — target: {root}   (mode: {'DEEP' if deep else 'fast'})")
    info("Detection & recon only — no auto-exploitation. Stay within authorized scope.")
    scope = _load_scope(scope_file, root)
    info(f"scope: {', '.join(scope)}")

    subs = _subdomains(root, outdir, scope)
    result["tools"].append({"tool": "subdomain-enum", "status": "done", "output": os.path.join(outdir, "subdomains.txt")})
    for s in subs:
        result["findings"].append(finding("recon.subdomain", s))

    live = _probe(subs, outdir)
    result["tools"].append({"tool": "httpx/dnsx", "status": "done", "output": os.path.join(outdir, "live.txt")})

    _ports(root, outdir, deep)
    _urls(root, live, outdir, deep)
    if _lines(os.path.join(outdir, "urls.txt")):
        result["findings"].append(finding(
            "recon.interesting_url",
            f"{len(_lines(os.path.join(outdir, 'urls.txt')))} URLs collected — review urls.txt for injectable params"))
    if deep:
        _content_discovery(live, outdir)
    else:
        info("Content discovery + screenshots run in --deep mode (slower).")
    if deep and have("gowitness"):
        banner("RECON — screenshots [deep] (gowitness)")
        run_live(["gowitness", "file", "-f", os.path.join(outdir, "live.txt"),
                  "--screenshot-path", os.path.join(outdir, "screenshots")], timeout=900)
    _fingerprint(root, live, outdir, result)
    _nuclei(outdir, result, deep)

    if not cve_intel.is_online():
        warn("CVE intel feeds unreachable (offline) — CVSS/KEV enrichment limited this run.")
    ok(f"recon complete — artifacts in {outdir}/")
    return result
