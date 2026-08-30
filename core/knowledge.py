#!/usr/bin/env python3
"""
core/knowledge.py — security-knowledge catalog (spec §31).

This module makes the platform's *knowledge* measurable and inspectable. It
does NOT run anything; it enumerates what the engine knows about — which attack
families are covered by the knowledge base, how many finding definitions exist
per family, and which broad security domains have coverage vs. are declared but
not yet backed by KB entries.

Everything is derived live from `knowledgebase.KB`, so the catalog can never
drift from reality or over-claim: the counts are exactly the definitions that
exist. This is the honesty layer for the "what do you cover?" question.
"""

from __future__ import annotations

# Human-readable metadata per KB id-prefix (the "family"). Description is short;
# the point is orientation, not documentation. Any family present in the KB but
# missing here still shows up (with a generated label) so nothing is hidden.
FAMILY_META: dict[str, dict] = {
    "web":          {"name": "Web application",          "domain": "web"},
    "api":          {"name": "API (OWASP API Top 10)",   "domain": "api"},
    "network":      {"name": "Network / host services",  "domain": "network"},
    "windows":      {"name": "Windows host / AD-adjacent","domain": "windows"},
    "linux":        {"name": "Linux host / privesc",     "domain": "linux"},
    "cloud":        {"name": "Cloud posture (IAM/storage/config)", "domain": "cloud"},
    "container":    {"name": "Container images",          "domain": "container"},
    "k8s":          {"name": "Kubernetes / orchestration","domain": "kubernetes"},
    "mobile":       {"name": "Mobile app (MASVS)",        "domain": "mobile"},
    "code":         {"name": "Source code / SCA / secrets","domain": "source"},
    "recon":        {"name": "Recon / attack surface",    "domain": "recon"},
    "db":           {"name": "Databases / data stores",   "domain": "database"},
    "crypto":       {"name": "Cryptography",              "domain": "crypto"},
    "supplychain":  {"name": "Software supply chain",     "domain": "supply_chain"},
    "availability": {"name": "Availability / resilience", "domain": "availability"},
}

# Broad security domains the platform aims to reason about (spec §30 breadth).
# A domain may be "covered" (KB entries exist for its family) or "declared"
# (recognised area we map to, but without dedicated KB definitions yet). We never
# pretend a declared-only domain is fully covered.
SECURITY_DOMAINS: dict[str, str] = {
    "web": "Web application vulnerabilities (injection, XSS, access control, SSRF, ...)",
    "api": "API security (BOLA/BFLA, mass assignment, excessive data, GraphQL)",
    "network": "Network & host service exposure and known-vulnerable services",
    "windows": "Windows host hardening / local privilege escalation",
    "linux": "Linux host hardening / local privilege escalation",
    "active_directory": "Active Directory / identity attack paths (via identity export)",
    "cloud": "Cloud posture: IAM, storage, encryption, logging, exposure",
    "container": "Container image vulnerabilities and misconfiguration",
    "kubernetes": "Kubernetes / orchestration security",
    "mobile": "Mobile application security (Android/iOS, MASVS)",
    "source": "Source code weaknesses, SCA, and committed secrets",
    "supply_chain": "Software supply chain (dependency confusion, integrity)",
    "database": "Database / data-store exposure and credentials",
    "crypto": "Cryptographic failures (hashing, randomness, TLS)",
    "memory_safety": "Memory-safety classes (buffer/UAF) — reasoned via CVE/SCA, no direct binary analysis",
    "wireless_iot": "Wireless / IoT — not directly scanned; reasoned via network exposure + CVEs",
    "identity": "Identity & authentication failures across web/API/cloud",
    "recon": "Attack-surface discovery / OSINT-style asset enumeration",
    "availability": "Availability & resilience (passive signals; no DoS)",
}

# Domains intentionally reasoned-about indirectly (never claim direct testing).
_INDIRECT_DOMAINS = {"memory_safety", "wireless_iot", "active_directory", "identity"}


def _kb():
    import knowledgebase as kb
    return kb.KB


def catalog() -> dict:
    """family -> {name, domain, count, ids:[...]} derived live from the KB."""
    kb = _kb()
    families: dict[str, dict] = {}
    for fid in kb:
        fam = fid.split(".")[0]
        meta = FAMILY_META.get(fam, {"name": fam.replace("_", " ").title(), "domain": fam})
        entry = families.setdefault(fam, {"name": meta["name"], "domain": meta["domain"],
                                          "count": 0, "ids": []})
        entry["count"] += 1
        entry["ids"].append(fid)
    for e in families.values():
        e["ids"].sort()
    return dict(sorted(families.items(), key=lambda kv: -kv[1]["count"]))


def domain_coverage() -> dict:
    """
    security-domain -> {"description", "status", "kb_entries"}.
      status = "covered"  : KB definitions exist for the domain's family
               "indirect" : reasoned via CVE/exports, not directly scanned
               "declared" : recognised area with no dedicated KB entries yet
    """
    cat = catalog()
    by_domain: dict[str, int] = {}
    for fam in cat.values():
        by_domain[fam["domain"]] = by_domain.get(fam["domain"], 0) + fam["count"]
    out: dict[str, dict] = {}
    for domain, desc in SECURITY_DOMAINS.items():
        n = by_domain.get(domain, 0)
        if n > 0:
            status = "covered"
        elif domain in _INDIRECT_DOMAINS:
            status = "indirect"
        else:
            status = "declared"
        out[domain] = {"description": desc, "status": status, "kb_entries": n}
    return out


def summary() -> dict:
    kb = _kb()
    cat = catalog()
    dom = domain_coverage()
    return {
        "kb_entries": len(kb),
        "families": len(cat),
        "family_counts": {f: c["count"] for f, c in cat.items()},
        "domains_total": len(dom),
        "domains_covered": sum(1 for d in dom.values() if d["status"] == "covered"),
        "domains_indirect": sum(1 for d in dom.values() if d["status"] == "indirect"),
        "domains_declared": sum(1 for d in dom.values() if d["status"] == "declared"),
        "disclaimer": "Knowledge is measurable, not exhaustive. Coverage counts are the "
                      "definitions that actually exist; new classes are added continuously.",
    }


def render() -> str:
    s = summary()
    cat = catalog()
    dom = domain_coverage()
    lines = ["SECURITY KNOWLEDGE CATALOG", ""]
    lines.append(f"  Knowledge-base entries : {s['kb_entries']} across {s['families']} families")
    lines.append(f"  Security domains       : {s['domains_covered']} covered, "
                 f"{s['domains_indirect']} indirect, {s['domains_declared']} declared "
                 f"(of {s['domains_total']})")
    lines.append("")
    lines.append("  Attack families (definitions):")
    for fam, e in cat.items():
        lines.append(f"    {fam:14} {e['count']:>3}  {e['name']}")
    lines.append("")
    lines.append("  Security domains:")
    marks = {"covered": "[x]", "indirect": "[~]", "declared": "[ ]"}
    for domain, d in dom.items():
        mark = marks.get(d["status"], "[ ]")
        n = f"({d['kb_entries']})" if d["kb_entries"] else ""
        lines.append(f"    {mark} {domain:16} {n:>5}  {d['description']}")
    lines.append("")
    lines.append("  Legend: [x] KB-backed  [~] reasoned indirectly (CVE/exports)  [ ] declared, no KB yet")
    lines.append("  NOTE: measurable knowledge, not a claim of covering every attack.")
    return "\n".join(lines)
