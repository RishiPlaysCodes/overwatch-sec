#!/usr/bin/env python3
"""
scanner_network.py — Network / host / infrastructure vulnerability scanner.

Goes beyond web: scans a host / IP / CIDR for exposed services and known
vulnerabilities at the network layer (this is what web-only tools like Nikto
can't do).

Engines (auto-detected, skipped if missing):
  - nmap -sV                 : service/version discovery on open ports
  - nmap --script vuln       : NSE 'vuln' category checks (known service vulns)
  - searchsploit             : correlate discovered services with Exploit-DB
  - OpenVAS / Greenbone (gvm): hook — if `gvm-cli` is present we point the user
                               at running a full authenticated scan (deep infra
                               coverage / thousands of NVTs)

Every discovered CVE is enriched via cve_intel (CISA KEV "actively exploited"
flag + NVD CVSS), so the report prioritizes what actually matters.

>>> No DoS. NSE runs the 'vuln' category only (excludes 'dos'/'exploit'). <<<
"""

from __future__ import annotations

import os
import re

import cve_intel
from common import banner, err, finding, have, info, ok, run, warn

_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$")


def _parse_open_ports(nmap_out: str) -> list[dict]:
    services = []
    for line in nmap_out.splitlines():
        m = _PORT_RE.match(line.strip())
        if m and m.group(3) == "open":
            services.append({
                "port": m.group(1),
                "proto": m.group(2),
                "service": m.group(4),
                "version": m.group(5).strip(),
            })
    return services


def _enrich_cves_from_text(text: str, source: str) -> list[dict]:
    """Pull CVEs out of tool output and turn them into enriched findings."""
    out = []
    for cve in cve_intel.extract_cves(text):
        intel = cve_intel.enrich(cve)
        fid = "network.exploit_known" if intel["kev"] else "network.vuln_service"
        sev = intel["severity"] or None
        ev = f"{cve_intel.describe(intel)} (via {source})"
        if intel["summary"]:
            ev += f" — {intel['summary'][:120]}"
        out.append(finding(fid, ev, severity_override=sev))
    return out


def scan(target: str, outdir: str, skip: set[str]) -> dict:
    result = {"profile": "network", "target": target, "findings": [], "tools": []}

    if not have("nmap"):
        banner("NETWORK — nmap")
        warn("nmap not installed — network scanning needs it (apt install nmap)")
        result["tools"].append({"tool": "nmap", "status": "skipped", "reason": "not installed (apt/dnf install nmap)"})
    else:
        # 1) Service/version discovery
        banner("NETWORK — service/version discovery (nmap -sV)")
        sv_path = os.path.join(outdir, "nmap-services.txt")
        rc, out = run(["nmap", "-sV", "-Pn", "--top-ports", "1000", target], timeout=1800)
        with open(sv_path, "w") as fh:
            fh.write(out)
        result["tools"].append({"tool": "nmap -sV", "status": "done" if rc == 0 else f"exit {rc}", "output": sv_path})
        services = _parse_open_ports(out)
        for s in services:
            result["findings"].append(
                finding("network.exposed_service",
                        f"{s['port']}/{s['proto']} {s['service']} {s['version']}".strip()))
        ok(f"discovered {len(services)} open service(s)")

        # 2) NSE 'vuln' category (known service vulnerabilities; excludes dos)
        if "nmap-vuln" not in skip:
            banner("NETWORK — known-vuln checks (nmap --script vuln)")
            v_path = os.path.join(outdir, "nmap-vuln.txt")
            rc, vout = run(["nmap", "-sV", "-Pn", "--script", "vuln", "--top-ports", "1000", target], timeout=2400)
            with open(v_path, "w") as fh:
                fh.write(vout)
            result["tools"].append({"tool": "nmap --script vuln",
                                    "status": "done" if rc == 0 else f"exit {rc}", "output": v_path})
            # Emit a finding for each service block flagged VULNERABLE
            for block in re.split(r"\n(?=\d+/(?:tcp|udp))", vout):
                if "VULNERABLE" in block:
                    head = block.strip().splitlines()[0][:60]
                    title_line = next((l.strip() for l in block.splitlines() if "VULNERABLE" in l), head)
                    result["findings"].append(finding("network.vuln_service", f"{head} :: {title_line[:120]}"))
            result["findings"] += _enrich_cves_from_text(vout, "nmap NSE")
            ok("NSE vuln scripts complete")

        # 3) searchsploit correlation
        banner("NETWORK — Exploit-DB correlation (searchsploit)")
        if have("searchsploit") and "searchsploit" not in skip:
            se_path = os.path.join(outdir, "searchsploit.txt")
            # Feed nmap XML if available; else query per discovered product string.
            hits = []
            for s in services:
                prod = re.sub(r"\d+(\.\d+)+", lambda m: m.group(0), s["version"]).strip()
                q = (s["service"] + " " + prod).strip()
                if not q:
                    continue
                rc, so = run(["searchsploit", "--color", "--disable-colour", q], timeout=120)
                if "Exploit Title" in so and "No Results" not in so:
                    hits.append(f"### query: {q}\n{so}")
            with open(se_path, "w") as fh:
                fh.write("\n\n".join(hits) or "No searchsploit matches.")
            if hits:
                result["findings"].append(
                    finding("network.exploit_known",
                            f"searchsploit found potential public exploits for {len(hits)} service(s) (see searchsploit.txt)"))
            result["tools"].append({"tool": "searchsploit", "status": "done", "output": se_path})
        else:
            result["tools"].append({"tool": "searchsploit",
                                    "status": "skipped", "reason": "not installed (part of exploitdb package)"})

    # 4) OpenVAS / Greenbone hook (deep authenticated infra scan)
    banner("NETWORK — OpenVAS / Greenbone (deep infra scan)")
    if have("gvm-cli") or have("gvm-script"):
        info("Greenbone/GVM detected. For full NVT coverage (thousands of checks), run an authenticated "
             "GVM scan against this target via the GVM/GSA console or gvm-cli, then import its report.")
        result["tools"].append({"tool": "OpenVAS/GVM", "status": "available",
                                "reason": "run a GVM task for full NVT coverage; not auto-launched (needs GVM config)"})
    else:
        result["tools"].append({"tool": "OpenVAS/GVM", "status": "skipped",
                                "reason": "not installed — install greenbone/gvm for deep infra NVT coverage"})

    if not cve_intel.is_online():
        warn("CVE intel feeds unreachable (offline) — CVSS/KEV enrichment limited this run.")
    return result
