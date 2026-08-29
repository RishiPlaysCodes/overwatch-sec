#!/usr/bin/env python3
"""
scanner_container.py — Container image vulnerability scanner.

Points at a container image reference (e.g. `nginx:1.21`, `myrepo/app:tag`) and
finds vulnerable OS/language packages and image misconfigurations.

Engines (auto-detected, skipped if missing):
  - trivy image  : OS + language package CVEs + secrets + misconfig
  - grype        : OS + language package CVEs (Anchore)

CVE ids in tool output are enriched via cve_intel (CISA KEV actively-exploited
flag + NVD CVSS) so Critical/High and in-the-wild issues bubble to the top.
"""

from __future__ import annotations

import os

import cve_intel
from common import banner, err, finding, have, ok, run, warn


def _enrich_cves(text: str, source: str) -> list[dict]:
    out = []
    for cve in cve_intel.extract_cves(text):
        intel = cve_intel.enrich(cve)
        fid = "network.exploit_known" if intel["kev"] else "container.cve"
        ev = f"{cve_intel.describe(intel)} (via {source})"
        out.append(finding(fid, ev, severity_override=intel["severity"]))
    return out


def scan(image: str, outdir: str, skip: set[str]) -> dict:
    result = {"profile": "container", "target": image, "findings": [], "tools": []}
    ran = False

    banner(f"CONTAINER — image scan: {image}")
    if have("trivy") and "trivy" not in skip:
        ran = True
        path = os.path.join(outdir, "trivy-image.txt")
        rc, out = run(["trivy", "image", "--scanners", "vuln,secret,misconfig", image], timeout=1800)
        with open(path, "w") as fh:
            fh.write(out)
        result["tools"].append({"tool": "trivy image", "status": "done" if rc in (0, 1) else f"exit {rc}", "output": path})
        result["findings"] += _enrich_cves(out, "trivy")
        if "root" in out.lower() and "user" in out.lower() and "should not be root" in out.lower():
            result["findings"].append(finding("container.misconfig", "Image runs as root (see trivy-image.txt)"))
        ok("trivy image scan complete")
    else:
        result["tools"].append({"tool": "trivy image", "status": "skipped",
                                "reason": "not installed (github.com/aquasecurity/trivy)"})

    banner("CONTAINER — tool: grype")
    if have("grype") and "grype" not in skip:
        ran = True
        path = os.path.join(outdir, "grype-image.txt")
        rc, out = run(["grype", image], timeout=1200)
        with open(path, "w") as fh:
            fh.write(out)
        result["tools"].append({"tool": "grype", "status": "done" if rc in (0, 1) else f"exit {rc}", "output": path})
        result["findings"] += _enrich_cves(out, "grype")
        ok("grype scan complete")
    else:
        result["tools"].append({"tool": "grype", "status": "skipped",
                                "reason": "not installed (github.com/anchore/grype)"})

    if not ran:
        warn("No container scanner installed. Install trivy or grype to scan images.")
    if not cve_intel.is_online():
        warn("CVE intel feeds unreachable (offline) — CVSS/KEV enrichment limited this run.")
    return result
