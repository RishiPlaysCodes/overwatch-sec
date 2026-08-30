#!/usr/bin/env python3
"""
attack_paths/mitre.py — map findings to MITRE ATT&CK techniques.

A lightweight, extensible mapping from finding-id prefixes / keywords to ATT&CK
technique ids + the kill-chain tactic. This is metadata-driven so new mappings
are added without code changes. It is NOT a claim of exhaustiveness.
"""

from __future__ import annotations

# finding-id (or prefix) -> (technique_id, technique_name, tactic)
TECHNIQUE_MAP = {
    # initial access / web exploitation
    "web.sqli":            ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "web.xss":             ("T1189", "Drive-by Compromise", "initial-access"),
    "web.fileupload":      ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "web.cve":             ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "network.vuln_service":("T1190", "Exploit Public-Facing Application", "initial-access"),
    "network.exploit_known":("T1203", "Exploitation for Client Execution", "execution"),
    "recon.exposed_panel": ("T1133", "External Remote Services", "initial-access"),
    "recon.subdomain_takeover": ("T1584", "Compromise Infrastructure", "resource-development"),
    # recon
    "recon.subdomain":     ("T1595", "Active Scanning", "reconnaissance"),
    "recon.interesting_url":("T1595", "Active Scanning", "reconnaissance"),
    "network.exposed_service": ("T1046", "Network Service Discovery", "discovery"),
    "recon.waf":           ("T1595", "Active Scanning", "reconnaissance"),
    # credential access / secrets
    "code.secret":         ("T1552", "Unsecured Credentials", "credential-access"),
    "recon.js_secret":     ("T1552", "Unsecured Credentials", "credential-access"),
    "mobile.secrets":      ("T1552", "Unsecured Credentials", "credential-access"),
    "web.cookie":          ("T1539", "Steal Web Session Cookie", "credential-access"),
    # cloud
    "cloud.iam_wildcard":  ("T1078", "Valid Accounts", "privilege-escalation"),
    "cloud.no_mfa":        ("T1078", "Valid Accounts", "initial-access"),
    "cloud.public_bucket": ("T1530", "Data from Cloud Storage", "collection"),
    "cloud.public_ip":     ("T1133", "External Remote Services", "initial-access"),
    "cloud.open_sg":       ("T1133", "External Remote Services", "initial-access"),
    "cloud.logging_off":   ("T1562", "Impair Defenses", "defense-evasion"),
    "cloud.unencrypted":   ("T1530", "Data from Cloud Storage", "collection"),
    # container / mobile config
    "container.cve":       ("T1610", "Deploy Container", "execution"),
    "container.misconfig": ("T1611", "Escape to Host", "privilege-escalation"),
    "mobile.exported":     ("T1409", "Stored Application Data", "collection"),
    "mobile.cleartext":    ("T1040", "Network Sniffing", "credential-access"),
    "mobile.debuggable":   ("T1626", "Abuse Elevation Control Mechanism", "privilege-escalation"),
    # config / info
    "web.header":          ("T1595", "Active Scanning", "reconnaissance"),
    "web.infoleak":        ("T1592", "Gather Victim Host Information", "reconnaissance"),
    "recon.dir_listing":   ("T1083", "File and Directory Discovery", "discovery"),
    # API
    "api.no_auth":         ("T1190", "Exploit Public-Facing Application", "initial-access"),
    "api.cors":            ("T1189", "Drive-by Compromise", "initial-access"),
    "api.graphql_introspection": ("T1592", "Gather Victim Host Information", "reconnaissance"),
    "api.docs_exposed":    ("T1592", "Gather Victim Host Information", "reconnaissance"),
    # Kubernetes
    "k8s.privileged":      ("T1611", "Escape to Host", "privilege-escalation"),
    "k8s.hostpath":        ("T1611", "Escape to Host", "privilege-escalation"),
    "k8s.rbac_wildcard":   ("T1078", "Valid Accounts", "privilege-escalation"),
    "k8s.hostnet":         ("T1040", "Network Sniffing", "credential-access"),
    "k8s.no_netpol":       ("T1210", "Exploitation of Remote Services", "lateral-movement"),
    # identity
    "identity.escalation_path": ("T1078", "Valid Accounts", "privilege-escalation"),
    # threat detection
    "threat.malicious_process": ("T1059", "Command and Scripting Interpreter", "execution"),
    "threat.c2_connection":     ("T1071", "Application Layer Protocol", "command-and-control"),
    "threat.persistence":       ("T1053", "Scheduled Task/Job", "persistence"),
    "threat.unexpected_admin":  ("T1136", "Create Account", "persistence"),
    "threat.suspicious_listener": ("T1571", "Non-Standard Port", "command-and-control"),
    "threat.risky_access_key":  ("T1078", "Valid Accounts", "persistence"),
}

# rough tactic ordering for path layout (kill-chain)
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "exfiltration", "impact",
]


def technique_for(finding_id: str):
    if finding_id in TECHNIQUE_MAP:
        return TECHNIQUE_MAP[finding_id]
    # prefix match (e.g. web.header.csp -> web.header)
    for key, val in TECHNIQUE_MAP.items():
        if finding_id.startswith(key):
            return val
    return None


def annotate(findings) -> None:
    """Attach MITRE technique ids to each finding in place."""
    for f in findings:
        t = technique_for(f.id)
        if t and t[0] not in f.mitre:
            f.mitre.append(t[0])
            f.tags.append(f"ATT&CK:{t[0]}:{t[2]}")


def tactic_of(finding_id: str) -> str:
    t = technique_for(finding_id)
    return t[2] if t else "discovery"
