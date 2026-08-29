#!/usr/bin/env python3
"""
scanner_cloud.py — Cloud & Infrastructure-as-Code vulnerability scanner.

Target can be:
  - a directory of IaC (Terraform .tf / CloudFormation .yaml/.json)  -> built-in checks + trivy/checkov
  - a live cloud account keyword: aws | azure | gcp                  -> prowler/scoutsuite (need creds)

Built-in IaC misconfig checks (no external tools):
  - public storage buckets (S3/GCS/Blob)
  - security groups / firewall rules open to 0.0.0.0/0
  - unencrypted data stores / volumes
  - wildcard IAM policies (Action:* / Resource:*)
  - public IPs on instances/DBs

Wrapped tools (auto-detected): checkov, trivy (config), prowler (AWS), scout (multi-cloud).
Every issue maps to the knowledge base (OWASP Cloud / CIS + CWE).
"""

from __future__ import annotations

import os
import re

from common import banner, err, finding, have, info, ok, run, warn

IAC_EXT = (".tf", ".tf.json", ".yaml", ".yml", ".json", ".template")
_PUBLIC_CIDR = "0.0.0.0/0"
_SENSITIVE_PORTS = {"22", "3389", "3306", "5432", "1433", "6379", "27017", "9200", "5984"}


def _iter_iac_files(path: str):
    for root, _dirs, files in os.walk(path):
        if any(seg in root for seg in (".git", ".terraform", "node_modules")):
            continue
        for f in files:
            if f.endswith(IAC_EXT):
                yield os.path.join(root, f)


def _builtin_iac_checks(path: str) -> list[dict]:
    out = []
    files = list(_iter_iac_files(path))
    info(f"scanning {len(files)} IaC file(s) with built-in rules")
    for fp in files:
        try:
            with open(fp, "r", errors="ignore") as fh:
                text = fh.read()
        except Exception:
            continue
        low = text.lower()
        rel = os.path.relpath(fp, path)

        # Public buckets
        if re.search(r'acl\s*=\s*"public-read(-write)?"', low) or '"publicaccessblockconfiguration"' in low and "false" in low:
            out.append(finding("cloud.public_bucket", f"{rel}: bucket ACL/public-access allows public"))
        if re.search(r'"?public_access_block(_configuration)?"?', low) and "block_public_acls = false" in low:
            out.append(finding("cloud.public_bucket", f"{rel}: public access block disabled"))

        # Open security groups / firewall to the world on sensitive ports
        if _PUBLIC_CIDR in text:
            # find nearby port refs
            for m in re.finditer(r'(from_port|to_port|source_ranges|cidr_blocks)[^\n]*', text, re.I):
                ctx = text[max(0, m.start() - 120): m.end() + 120]
                if _PUBLIC_CIDR in ctx:
                    ports = set(re.findall(r'\b(\d{2,5})\b', ctx))
                    hit = ports & _SENSITIVE_PORTS
                    if hit or "ingress" in ctx.lower():
                        out.append(finding("cloud.open_sg",
                                           f"{rel}: ingress from {_PUBLIC_CIDR}" +
                                           (f" on sensitive port(s) {sorted(hit)}" if hit else "")))
                        break

        # Unencrypted resources
        if re.search(r'(encrypted|storage_encrypted|server_side_encryption[^\n]*)\s*=\s*false', low):
            out.append(finding("cloud.unencrypted", f"{rel}: encryption explicitly disabled"))

        # Wildcard IAM
        if re.search(r'"?action"?\s*[=:]\s*\[?\s*"\*"', low) or '"action": "*"' in low:
            if re.search(r'"?resource"?\s*[=:]\s*\[?\s*"\*"', low) or '"resource": "*"' in low:
                out.append(finding("cloud.iam_wildcard", f"{rel}: IAM policy with Action:* and Resource:*"))
            else:
                out.append(finding("cloud.iam_wildcard", f"{rel}: IAM policy uses Action:*"))

        # Public IP on instances/DB
        if re.search(r'(associate_public_ip_address|publicly_accessible|assign_public_ip)\s*=\s*true', low):
            out.append(finding("cloud.public_ip", f"{rel}: resource assigned a public IP / publicly accessible"))

        # Logging disabled
        if re.search(r'(enable_logging|logging)\s*=\s*false', low):
            out.append(finding("cloud.logging_off", f"{rel}: logging disabled"))

    # de-dup identical (id, evidence)
    seen, uniq = set(), []
    for f in out:
        k = (f["id"], f["evidence"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


def _scan_iac_dir(path: str, outdir: str, skip: set[str]) -> dict:
    result = {"profile": "cloud", "target": path, "findings": [], "tools": []}
    banner(f"CLOUD/IaC — built-in misconfig checks on {path}")
    result["findings"] += _builtin_iac_checks(path)

    # checkov
    banner("CLOUD/IaC — tool: checkov")
    if have("checkov") and "checkov" not in skip:
        outfile = os.path.join(outdir, "checkov.txt")
        rc, out = run(["checkov", "-d", path, "--compact", "--quiet"], timeout=900)
        with open(outfile, "w") as fh:
            fh.write(out)
        result["tools"].append({"tool": "checkov", "status": "done", "output": outfile})
    else:
        result["tools"].append({"tool": "checkov", "status": "skipped", "reason": "not installed (pip install checkov)"})

    # trivy config
    banner("CLOUD/IaC — tool: trivy config")
    if have("trivy") and "trivy" not in skip:
        outfile = os.path.join(outdir, "trivy-config.txt")
        rc, out = run(["trivy", "config", path], timeout=900)
        with open(outfile, "w") as fh:
            fh.write(out)
        result["tools"].append({"tool": "trivy", "status": "done", "output": outfile})
    else:
        result["tools"].append({"tool": "trivy", "status": "skipped", "reason": "not installed (github.com/aquasecurity/trivy)"})
    return result


def _scan_live_cloud(provider: str, outdir: str, skip: set[str]) -> dict:
    result = {"profile": "cloud", "target": provider, "findings": [], "tools": []}
    banner(f"CLOUD — live account audit ({provider}) — requires configured credentials")
    warn("Live cloud audit reads your account via prowler/scoutsuite. Ensure credentials are for an account you own.")

    if provider == "aws":
        if have("prowler") and "prowler" not in skip:
            outfile = os.path.join(outdir, "prowler.txt")
            rc, out = run(["prowler", "aws", "-M", "text", "--no-banner"], timeout=1800)
            with open(outfile, "w") as fh:
                fh.write(out)
            result["tools"].append({"tool": "prowler", "status": "done" if rc in (0, 3) else f"exit {rc}", "output": outfile})
        else:
            result["tools"].append({"tool": "prowler", "status": "skipped", "reason": "not installed (pip install prowler)"})

    if have("scout") and "scoutsuite" not in skip:
        outfile = os.path.join(outdir, f"scoutsuite-{provider}")
        rc, out = run(["scout", provider, "--report-dir", outfile, "--no-browser"], timeout=1800)
        result["tools"].append({"tool": "scoutsuite", "status": "done" if rc == 0 else f"exit {rc}", "output": outfile})
    else:
        result["tools"].append({"tool": "scoutsuite", "status": "skipped", "reason": "not installed (pip install scoutsuite)"})

    if not result["tools"] or all(t["status"].startswith("skip") for t in result["tools"]):
        info("No live-cloud tools available. Install prowler/scoutsuite, or scan an IaC directory instead.")
    return result


def scan(target: str, outdir: str, skip: set[str]) -> dict:
    if target in ("aws", "azure", "gcp"):
        return _scan_live_cloud(target, outdir, skip)
    if os.path.isdir(target):
        return _scan_iac_dir(target, outdir, skip)
    err(f"cloud target must be a provider (aws/azure/gcp) or an IaC directory: {target}")
    return {"profile": "cloud", "target": target, "findings": [], "tools": []}
