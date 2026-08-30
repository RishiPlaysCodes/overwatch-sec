#!/usr/bin/env python3
"""
scanner_linux.py — Linux host security assessment (from an AUTHORIZED export).

You collect host data on a system you're authorized to assess (with the bundled
collector or your own) and hand the resulting JSON to overwatch. This scanner is
a pure, offline analyzer — it never logs into or executes anything on a remote
host. It surfaces local-privilege-escalation and hardening issues and clearly
distinguishes "possible" from "validated".

Accepted input (JSON), any subset:
{
  "kernel": "5.4.0-42-generic",
  "os": "Ubuntu 20.04",
  "suid": ["/usr/bin/find", "/usr/bin/passwd", "/tmp/backup"],
  "sudo": ["(ALL) NOPASSWD: /usr/bin/vim", "(ALL) ALL"],
  "world_writable": ["/etc/cron.daily/backup", "/opt/app/run.sh"],
  "cron": ["* * * * * root /opt/app/run.sh"],
  "capabilities": ["/usr/bin/python3.8 = cap_setuid+ep"],
  "sshd_config": {"PermitRootLogin": "yes", "PasswordAuthentication": "yes"},
  "packages": [{"name": "sudo", "version": "1.8.31", "cve": "CVE-2021-3156"}]
}

The bundled collector script text is available via collector_script() so the
operator can run it themselves on an authorized host.
"""

from __future__ import annotations

import json
import os
import re

from common import banner, err, finding, info, ok, warn

# well-known GTFOBins-style abusable SUID/sudo binaries (subset, extensible)
GTFO = {"find", "vim", "vi", "nano", "less", "more", "man", "awk", "gawk", "nmap",
        "python", "python3", "perl", "ruby", "bash", "sh", "cp", "mv", "tar",
        "zip", "env", "ftp", "gdb", "make", "node", "socat", "tee", "dd"}


def _basename_stem(p: str) -> str:
    b = os.path.basename(p)
    return re.sub(r"[0-9.]+$", "", b)  # python3.8 -> python


def _check_suid(items, out):
    for path in items or []:
        stem = _basename_stem(path)
        if stem in GTFO:
            out.append(finding("linux.suid", f"{path} (abusable SUID/SGID — GTFOBins '{stem}')"))
        elif path.startswith(("/tmp/", "/home/", "/var/tmp/", "/dev/shm/")):
            out.append(finding("linux.suid", f"{path} (unexpected SUID in user-writable location)"))


def _check_sudo(items, out):
    for rule in items or []:
        low = rule.lower()
        if "nopasswd" in low:
            out.append(finding("linux.sudo", f"NOPASSWD rule: {rule}"))
        elif re.search(r"\(all\)\s*all", low) or any(_basename_stem(w) in GTFO for w in rule.split()):
            out.append(finding("linux.sudo", f"shell-capable/broad sudo rule: {rule}"))


def _check_world_writable(items, out):
    for p in items or []:
        sev = "high" if p.startswith(("/etc/", "/usr/", "/opt/", "/bin", "/sbin")) else None
        out.append(finding("linux.world_writable", f"world-writable: {p}", severity_override=sev))


def _check_cron(items, out):
    for c in items or []:
        if "root" in c or re.search(r"/(tmp|home|opt|var/tmp)/", c):
            out.append(finding("linux.cron", f"scheduled job: {c.strip()[:120]}"))


def _check_caps(items, out):
    dangerous = ("cap_setuid", "cap_setgid", "cap_dac_override", "cap_sys_admin",
                 "cap_dac_read_search", "cap_sys_ptrace")
    for c in items or []:
        if any(d in c.lower() for d in dangerous):
            out.append(finding("linux.capabilities", f"capability: {c}"))


def _check_ssh(cfg, out):
    if not isinstance(cfg, dict):
        return
    if str(cfg.get("PermitRootLogin", "")).lower() in ("yes", "prohibit-password"):
        out.append(finding("linux.ssh_config", f"PermitRootLogin={cfg.get('PermitRootLogin')}"))
    if str(cfg.get("PasswordAuthentication", "")).lower() == "yes":
        out.append(finding("linux.ssh_config", "PasswordAuthentication=yes"))


def _check_packages(kernel, packages, out):
    import cve_intel
    for p in packages or []:
        cve = p.get("cve")
        if cve:
            intel = cve_intel.enrich(cve)
            fid = "linux.kernel_outdated"
            out.append(finding(fid, f"{p.get('name')} {p.get('version')}: {cve_intel.describe(intel)}",
                               severity_override=intel["severity"]))
    if kernel and re.search(r"\b[2-4]\.", str(kernel)):
        out.append(finding("linux.kernel_outdated", f"kernel {kernel} (old series — check local-privesc CVEs)"))


def scan(target: str, outdir: str, skip: set) -> dict:
    result = {"profile": "linux", "target": target, "findings": [], "tools": []}
    banner(f"LINUX — host assessment from export: {target}")
    if not os.path.isfile(target):
        warn("Linux assessment expects a host-data export (JSON). Generate it on an "
             "authorized host with the bundled collector, then pass its path.")
        result["tools"].append({"tool": "linux-collector", "status": "skipped",
                                "reason": "no export file provided"})
        return result
    try:
        with open(target, "r", errors="ignore") as fh:
            data = json.load(fh)
    except Exception as e:
        err(f"could not parse export: {e}")
        return result

    out = []
    _check_suid(data.get("suid"), out)
    _check_sudo(data.get("sudo"), out)
    _check_world_writable(data.get("world_writable"), out)
    _check_cron(data.get("cron"), out)
    _check_caps(data.get("capabilities"), out)
    _check_ssh(data.get("sshd_config"), out)
    _check_packages(data.get("kernel"), data.get("packages"), out)
    result["findings"] = out
    ok(f"{len(out)} Linux host finding(s)")
    result["tools"].append({"tool": "linux-host-audit", "status": "done"})
    return result


def collector_script() -> str:
    """A read-only collector the operator can run on an AUTHORIZED host."""
    return r"""#!/usr/bin/env bash
# overwatch Linux collector — READ ONLY. Run on a host you are authorized to assess.
# Produces host.json for: overwatch host.json --type linux
set -u
j() { python3 - "$@" <<'PY'
import json,sys; print(json.dumps(sys.argv[1]))
PY
}
{
  echo "{"
  echo "\"kernel\": $(uname -r | j -),"
  echo "\"os\": $( (. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME") | j -),"
  printf '"suid": ['; find / -perm -4000 -type f 2>/dev/null | head -200 | awk '{printf "%s\"%s\"", (NR>1?",":""), $0}'; echo '],'
  printf '"world_writable": ['; find /etc /usr /opt -perm -0002 -type f 2>/dev/null | head -100 | awk '{printf "%s\"%s\"", (NR>1?",":""), $0}'; echo '],'
  printf '"capabilities": ['; getcap -r / 2>/dev/null | head -100 | awk '{printf "%s\"%s\"", (NR>1?",":""), $0}'; echo '],'
  echo "\"sshd_config\": {\"PermitRootLogin\": $(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 | j -), \"PasswordAuthentication\": $(grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 | j -)}"
  echo "}"
} 
"""
