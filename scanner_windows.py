#!/usr/bin/env python3
"""
scanner_windows.py — Windows host security assessment (from an AUTHORIZED export).

Offline analyzer for Windows host data you collected on a system you're
authorized to assess. It never connects to or executes on a remote host. It
flags local-privesc and exposure issues; for Active Directory *attack paths*,
use --identity-file (attack_paths.identity / BloodHound connector).

Accepted input (JSON), any subset:
{
  "os": "Windows Server 2019",
  "hotfix_missing": [{"kb": "KB5005565", "cve": "CVE-2021-34527"}],
  "services": [
     {"name": "MyApp", "path": "C:\\Program Files\\My App\\app.exe", "writable_dir": true,
      "binary_writable_by_users": false}
  ],
  "exposed": {"smb": true, "smbv1": true, "signing": false,
              "rdp": true, "nla": false, "winrm": true},
  "credentials": {"autologon": true, "unattend": true, "gpp_cpassword": false, "lsass_readable": true}
}
"""

from __future__ import annotations

import json
import os

from common import banner, err, finding, ok, warn


def _check_services(services, out):
    for s in services or []:
        path = s.get("path", "")
        if " " in path and not path.strip().startswith('"') and s.get("writable_dir"):
            out.append(finding("windows.unquoted_service",
                               f"service '{s.get('name')}' unquoted path with writable dir: {path}"))
        if s.get("binary_writable_by_users") or s.get("config_writable_by_users"):
            out.append(finding("windows.weak_service_perms",
                               f"service '{s.get('name')}' binary/config writable by non-admins"))


def _check_exposed(exp, out):
    if not isinstance(exp, dict):
        return
    if exp.get("smb"):
        detail = "SMB reachable"
        if exp.get("smbv1"):
            detail += " + SMBv1 enabled"
        if exp.get("signing") is False:
            detail += " + signing not required"
        sev = "high" if (exp.get("smbv1") or exp.get("signing") is False) else "medium"
        out.append(finding("windows.smb_exposed", detail, severity_override=sev))
    if exp.get("rdp"):
        out.append(finding("windows.rdp_exposed",
                           "RDP reachable" + (" (NLA disabled)" if exp.get("nla") is False else "")))
    if exp.get("winrm"):
        out.append(finding("windows.winrm_exposed", "WinRM reachable"))


def _check_credentials(cred, out):
    if not isinstance(cred, dict):
        return
    hits = [k for k in ("autologon", "unattend", "gpp_cpassword", "lsass_readable") if cred.get(k)]
    if hits:
        out.append(finding("windows.credential_exposure", "credential material: " + ", ".join(hits)))


def _check_patches(items, out):
    import cve_intel
    for h in items or []:
        cve = h.get("cve")
        if cve:
            intel = cve_intel.enrich(cve)
            out.append(finding("windows.patch_missing",
                               f"missing {h.get('kb', '?')}: {cve_intel.describe(intel)}",
                               severity_override=intel["severity"]))
        else:
            out.append(finding("windows.patch_missing", f"missing update {h.get('kb', '?')}"))


def scan(target: str, outdir: str, skip: set) -> dict:
    result = {"profile": "windows", "target": target, "findings": [], "tools": []}
    banner(f"WINDOWS — host assessment from export: {target}")
    if not os.path.isfile(target):
        warn("Windows assessment expects a host-data export (JSON). Collect it on an "
             "authorized host, then pass its path. For AD attack paths use --identity-file.")
        result["tools"].append({"tool": "windows-collector", "status": "skipped",
                                "reason": "no export file provided"})
        return result
    try:
        with open(target, "r", errors="ignore") as fh:
            data = json.load(fh)
    except Exception as e:
        err(f"could not parse export: {e}")
        return result

    out = []
    _check_services(data.get("services"), out)
    _check_exposed(data.get("exposed"), out)
    _check_credentials(data.get("credentials"), out)
    _check_patches(data.get("hotfix_missing"), out)
    result["findings"] = out
    ok(f"{len(out)} Windows host finding(s)")
    result["tools"].append({"tool": "windows-host-audit", "status": "done"})
    return result
