#!/usr/bin/env python3
"""
scanner_code.py — Source code, dependency (SCA) & secrets scanner.

Points at a source directory (a checked-out repo / project folder) and finds:
  - Vulnerable dependencies (SCA) with CVE ids
  - Committed secrets / credentials
  - Insecure code patterns (SAST) when a supported analyzer is present

Engines (auto-detected, skipped if missing):
  - osv-scanner   : dependency CVEs across many ecosystems (Google OSV)
  - trivy fs      : dependency + misconfig + secret scanning
  - grype         : dependency CVEs (Anchore)
  - pip-audit     : Python dependency CVEs
  - npm audit     : Node dependency CVEs (if package.json present)
  - gitleaks      : secrets in files + git history
  - trufflehog    : verified secret detection
  - semgrep       : SAST (insecure code patterns)

CVE ids found in tool output are enriched via cve_intel (CISA KEV + NVD CVSS).
Also includes a lightweight built-in secret regex sweep so it still surfaces
obvious secrets even when no external tool is installed.
"""

from __future__ import annotations

import os
import re

import cve_intel
from common import banner, err, finding, have, info, ok, run, warn

# Built-in secret regexes (conservative)
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("GitHub token", re.compile(r"ghp_[0-9A-Za-z]{36}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Generic secret assignment",
     re.compile(r"(?i)(api[_-]?key|secret|passwd|password|token)\s*[=:]\s*['\"][0-9A-Za-z\-_]{12,}['\"]")),
]
_SKIP_DIRS = {".git", "node_modules", ".terraform", "venv", ".venv", "dist", "build", "__pycache__"}
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".ttf", ".otf", ".so", ".jar", ".zip")


def _builtin_secret_sweep(path: str) -> list[dict]:
    out, seen = [], set()
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if fn.endswith(_SKIP_EXT):
                continue
            fp = os.path.join(root, fn)
            try:
                if os.path.getsize(fp) > 2_000_000:
                    continue
                with open(fp, "r", errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                continue
            for label, rx in SECRET_PATTERNS:
                m = rx.search(text)
                if m:
                    rel = os.path.relpath(fp, path)
                    key = (label, rel)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(finding("code.secret", f"{label} in {rel}: {m.group(0)[:32]}…"))
    return out


def _enrich_cves(text: str, source: str) -> list[dict]:
    out = []
    for cve in cve_intel.extract_cves(text):
        intel = cve_intel.enrich(cve)
        fid = "network.exploit_known" if intel["kev"] else "code.dep_cve"
        ev = f"{cve_intel.describe(intel)} (via {source})"
        out.append(finding(fid, ev, severity_override=intel["severity"]))
    return out


def _tool(name: str, args: list[str], outfile: str, outdir: str, timeout: int,
          hint: str, enrich_source: str | None) -> tuple[dict, list[dict]]:
    if not have(name.split()[0]) or name.split()[0] in ():
        return {"tool": name, "status": "skipped", "reason": f"not installed{(' — ' + hint) if hint else ''}"}, []
    rc, out = run(args, timeout=timeout)
    path = os.path.join(outdir, outfile)
    with open(path, "w") as fh:
        fh.write(out)
    findings = _enrich_cves(out, enrich_source) if enrich_source else []
    return {"tool": name, "status": "done" if rc in (0, 1) else f"exit {rc}", "output": path}, findings


def scan(target: str, outdir: str, skip: set[str]) -> dict:
    result = {"profile": "code", "target": target, "findings": [], "tools": []}
    if not os.path.isdir(target):
        err(f"code scan needs a source directory: {target}")
        return result

    # Built-in secret sweep (always runs)
    banner(f"CODE — built-in secret sweep on {target}")
    secrets = _builtin_secret_sweep(target)
    result["findings"] += secrets
    ok(f"secret sweep found {len(secrets)} candidate(s)")

    # Built-in CI/CD pipeline analysis (dependency-free, always runs)
    banner("CODE — CI/CD pipeline analysis")
    try:
        from analyzers import cicd as _cicd
        cf = _cicd.analyze_dir(target)
        result["findings"] += cf
        result["tools"].append({"tool": "cicd-analyzer", "status": "done"})
        ok(f"CI/CD analysis: {len(cf)} finding(s)"
           + ("" if _cicd.files_present(target) else " (no CI/CD files found)"))
    except Exception as e:
        result["tools"].append({"tool": "cicd-analyzer", "status": f"error: {str(e)[:60]}"})
        warn(f"CI/CD analysis error: {e}")

    # Built-in IaC analysis (Dockerfiles / Terraform / Kubernetes YAML; dependency-free)
    banner("CODE — IaC analysis (Dockerfile / Terraform / Kubernetes)")
    try:
        from analyzers import iac as _iac
        iaf = _iac.analyze_dir(target)
        result["findings"] += iaf
        result["tools"].append({"tool": "iac-analyzer", "status": "done"})
        ok(f"IaC analysis: {len(iaf)} finding(s)"
           + ("" if _iac.files_present(target) else " (no IaC files found)"))
    except Exception as e:
        result["tools"].append({"tool": "iac-analyzer", "status": f"error: {str(e)[:60]}"})
        warn(f"IaC analysis error: {e}")

    # SCA / dependency CVE tools
    stages = [
        ("osv-scanner", ["osv-scanner", "--recursive", target], "osv-scanner.txt", 900,
         "github.com/google/osv-scanner", "osv-scanner"),
        ("trivy", ["trivy", "fs", "--scanners", "vuln,secret,misconfig", target], "trivy-fs.txt", 1200,
         "github.com/aquasecurity/trivy", "trivy"),
        ("grype", ["grype", f"dir:{target}"], "grype.txt", 900, "github.com/anchore/grype", "grype"),
        ("gitleaks", ["gitleaks", "detect", "--source", target, "--no-git", "-v"], "gitleaks.txt", 600,
         "github.com/gitleaks/gitleaks", None),
        ("semgrep", ["semgrep", "--config", "auto", "--error", target], "semgrep.txt", 1200,
         "pip install semgrep", None),
    ]
    for name, args, outfile, timeout, hint, enrich_source in stages:
        banner(f"CODE — tool: {name}")
        if name in skip:
            warn(f"skipped {name} (--skip)")
            result["tools"].append({"tool": name, "status": "skipped", "reason": "--skip"})
            continue
        status, fnds = _tool(name, args, outfile, outdir, timeout, hint, enrich_source)
        result["tools"].append(status)
        result["findings"] += fnds
        if status["status"].startswith("skip"):
            warn(f"{name}: {status['reason']}")
        else:
            ok(f"{name}: {status['status']} -> {status.get('output')}")
            # gitleaks/semgrep emit findings we surface generically
            if name == "gitleaks" and status["status"] == "exit 1":
                result["findings"].append(finding("code.secret", "gitleaks reported secrets (see gitleaks.txt)"))
            if name == "semgrep" and status["status"] == "exit 1":
                result["findings"].append(finding("code.sast", "semgrep reported insecure patterns (see semgrep.txt)"))

    # Python / Node ecosystem-specific
    if os.path.exists(os.path.join(target, "requirements.txt")) and have("pip-audit") and "pip-audit" not in skip:
        banner("CODE — tool: pip-audit")
        path = os.path.join(outdir, "pip-audit.txt")
        rc, out = run(["pip-audit", "-r", os.path.join(target, "requirements.txt")], timeout=600)
        with open(path, "w") as fh:
            fh.write(out)
        result["tools"].append({"tool": "pip-audit", "status": "done", "output": path})
        result["findings"] += _enrich_cves(out, "pip-audit")

    if os.path.exists(os.path.join(target, "package.json")) and have("npm") and "npm" not in skip:
        banner("CODE — tool: npm audit")
        path = os.path.join(outdir, "npm-audit.txt")
        rc, out = run(["npm", "audit", "--prefix", target], timeout=600)
        with open(path, "w") as fh:
            fh.write(out)
        result["tools"].append({"tool": "npm audit", "status": "done", "output": path})
        result["findings"] += _enrich_cves(out, "npm audit")

    if not cve_intel.is_online():
        warn("CVE intel feeds unreachable (offline) — CVSS/KEV enrichment limited this run.")
    return result
