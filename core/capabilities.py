#!/usr/bin/env python3
"""
core/capabilities.py — tool capability registry.

Describes every external tool the platform can orchestrate: which target kinds
it applies to, its risk level, and whether it's installed. The orchestrator uses
this to *choose* tools intelligently (spec §10) instead of blindly running
everything, and to report tool availability in the coverage section.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class Tool:
    name: str
    kinds: tuple                      # target kinds this tool serves
    risk: str = "passive"             # passive|safe_active|validation|intrusive
    modes: tuple = ("fast", "deep")   # which modes use it
    version_cmd: tuple = ()           # e.g. ("nmap","--version")
    note: str = ""

    def available(self) -> bool:
        return shutil.which(self.name) is not None

    def version(self) -> str:
        if not self.version_cmd or not self.available():
            return ""
        try:
            out = subprocess.run(self.version_cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, timeout=8).stdout
            return out.strip().splitlines()[0][:60] if out.strip() else ""
        except Exception:
            return ""


# The registry. Extend by appending — the engine adapts automatically.
REGISTRY: list[Tool] = [
    # recon
    Tool("subfinder", ("recon",), "passive", version_cmd=("subfinder", "-version")),
    Tool("assetfinder", ("recon",), "passive"),
    Tool("amass", ("recon",), "passive", modes=("deep",)),
    Tool("dnsx", ("recon",), "passive", version_cmd=("dnsx", "-version")),
    Tool("httpx", ("recon", "web", "api"), "safe_active", version_cmd=("httpx", "-version")),
    Tool("naabu", ("recon", "network"), "safe_active", version_cmd=("naabu", "-version")),
    Tool("katana", ("recon", "web"), "safe_active", modes=("deep",)),
    Tool("gau", ("recon", "web"), "passive"),
    Tool("waybackurls", ("recon", "web"), "passive"),
    Tool("gowitness", ("recon",), "safe_active", modes=("deep",)),
    Tool("ffuf", ("recon", "web"), "safe_active", modes=("deep",)),
    Tool("feroxbuster", ("recon", "web"), "safe_active", modes=("deep",)),
    Tool("wafw00f", ("recon", "web"), "passive"),
    Tool("wpscan", ("web",), "safe_active", modes=("deep",)),
    # web / vuln
    Tool("nuclei", ("recon", "web", "api", "network"), "safe_active", version_cmd=("nuclei", "-version")),
    Tool("nikto", ("web",), "safe_active", modes=("deep",)),
    Tool("whatweb", ("web", "recon"), "passive"),
    Tool("testssl.sh", ("web", "network"), "passive"),
    Tool("sqlmap", ("web", "api"), "validation", modes=("deep",), note="detection/validation only"),
    Tool("zap", ("web", "api"), "safe_active", modes=("deep",)),
    # network
    Tool("nmap", ("network", "web", "recon"), "safe_active", version_cmd=("nmap", "--version")),
    Tool("searchsploit", ("network",), "passive"),
    # mobile
    Tool("apkleaks", ("mobile",), "passive"),
    Tool("apktool", ("mobile",), "passive"),
    Tool("jadx", ("mobile",), "passive"),
    # cloud / iac / k8s
    Tool("checkov", ("cloud", "kubernetes"), "passive"),
    Tool("trivy", ("cloud", "container", "code", "kubernetes"), "passive", version_cmd=("trivy", "--version")),
    Tool("prowler", ("cloud",), "safe_active", modes=("deep",)),
    Tool("scout", ("cloud",), "safe_active", modes=("deep",)),
    Tool("kube-bench", ("kubernetes",), "safe_active", modes=("deep",)),
    # code / sca / secrets
    Tool("semgrep", ("code",), "passive", modes=("deep",)),
    Tool("gitleaks", ("code",), "passive"),
    Tool("grype", ("code", "container"), "passive"),
    Tool("osv-scanner", ("code",), "passive"),
    Tool("pip-audit", ("code",), "passive"),
]


def for_kind(kind: str) -> list[Tool]:
    return [t for t in REGISTRY if kind in t.kinds]


def available_tools() -> list[Tool]:
    return [t for t in REGISTRY if t.available()]


def snapshot() -> dict:
    """A serializable view of tool availability for the report/coverage section."""
    out = {"available": [], "unavailable": []}
    for t in REGISTRY:
        entry = {"name": t.name, "kinds": list(t.kinds), "risk": t.risk}
        if t.available():
            v = t.version()
            if v:
                entry["version"] = v
            out["available"].append(entry)
        else:
            out["unavailable"].append(entry)
    return out
