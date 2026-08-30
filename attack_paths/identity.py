#!/usr/bin/env python3
"""
attack_paths/identity.py — identity attack-path analysis (AD + cloud).

BloodHound-style analysis WITHOUT touching a live directory: it ingests an
identity graph *export* (JSON you provide from an authorized environment) and
computes privilege-escalation and lateral-movement paths from low-privileged
principals to high-value targets.

This is pure graph analysis over data you already collected — no live AD/cloud
attacks, no credential use, no exploitation. Feed it output you exported with
authorized tooling (BloodHound, ScoutSuite, Prowler, `az`/`aws`/`gcloud` dumps).

Input schema (identity export JSON):
{
  "nodes": [
    {"id": "user:alice",  "type": "user",  "tier": "low",  "label": "alice"},
    {"id": "group:helpdesk","type":"group"},
    {"id": "role:AdminRole","type":"role","high_value": true},
    {"id": "host:DC01",   "type": "computer", "high_value": true}
  ],
  "edges": [
    {"src": "user:alice", "dst": "group:helpdesk", "rel": "MemberOf"},
    {"src": "group:helpdesk", "dst": "role:AdminRole", "rel": "CanAssume"},
    {"src": "role:AdminRole", "dst": "host:DC01", "rel": "AdminTo"}
  ]
}

`high_value: true` (or type in {domain, tenant, kms, secretstore}) marks a
crown-jewel. Findings are produced for each principal->crown-jewel path.
"""

from __future__ import annotations

import json

from core.findings import Finding

# escalation-relevant edge relations -> (severity, MITRE technique, tactic)
ESCALATION_EDGES = {
    "MemberOf":        ("info", "T1069", "discovery"),
    "CanAssume":       ("high", "T1078", "privilege-escalation"),
    "AssumeRole":      ("high", "T1078", "privilege-escalation"),
    "AdminTo":         ("high", "T1078", "lateral-movement"),
    "HasSession":      ("high", "T1550", "lateral-movement"),
    "CanRDP":          ("medium", "T1021", "lateral-movement"),
    "CanPSRemote":     ("medium", "T1021", "lateral-movement"),
    "Owns":            ("high", "T1098", "privilege-escalation"),
    "WriteDacl":       ("high", "T1222", "privilege-escalation"),
    "WriteOwner":      ("high", "T1098", "privilege-escalation"),
    "GenericAll":      ("high", "T1098", "privilege-escalation"),
    "GenericWrite":    ("high", "T1098", "privilege-escalation"),
    "ForceChangePassword": ("high", "T1098", "credential-access"),
    "AddMember":       ("high", "T1098", "privilege-escalation"),
    "AllowedToDelegate": ("high", "T1187", "privilege-escalation"),
    "TrustedBy":       ("medium", "T1482", "lateral-movement"),
    "PassRole":        ("high", "T1078", "privilege-escalation"),
    "AttachPolicy":    ("high", "T1098", "privilege-escalation"),
    "CreateAccessKey": ("high", "T1098", "credential-access"),
}

_HV_TYPES = {"domain", "tenant", "kms", "secretstore", "keyvault"}
_SEV_W = {"critical": 40, "high": 30, "medium": 15, "low": 5, "info": 1}


class IdentityGraph:
    def __init__(self, data: dict):
        self.nodes = {n["id"]: n for n in data.get("nodes", [])}
        self.adj: dict[str, list] = {}
        for e in data.get("edges", []):
            self.adj.setdefault(e["src"], []).append((e["dst"], e.get("rel", "")))

    def is_high_value(self, nid: str) -> bool:
        n = self.nodes.get(nid, {})
        return bool(n.get("high_value")) or n.get("type") in _HV_TYPES

    def entry_principals(self) -> list[str]:
        """Low-tier / regular users are realistic attacker starting points."""
        out = []
        for nid, n in self.nodes.items():
            if n.get("type") in ("user", "serviceaccount", "identity"):
                if n.get("tier", "low") != "high" and not n.get("high_value"):
                    out.append(nid)
        return out or list(self.nodes)

    def paths_to_crown_jewels(self, start: str, max_len: int = 10, max_paths: int = 50):
        results = []

        def dfs(nid, path, rels, seen):
            if len(results) >= max_paths or len(path) > max_len:
                return
            if self.is_high_value(nid) and len(path) > 1:
                results.append((list(path), list(rels)))
                # keep exploring for deeper jewels too
            for dst, rel in self.adj.get(nid, []):
                if dst in seen:
                    continue
                seen.add(dst)
                path.append(dst); rels.append(rel)
                dfs(dst, path, rels, seen)
                path.pop(); rels.pop(); seen.discard(dst)

        dfs(start, [start], [], {start})
        return results


def _label(g: IdentityGraph, nid: str) -> str:
    n = g.nodes.get(nid, {})
    return n.get("label") or nid


def _path_severity(rels: list[str]) -> str:
    worst = "info"
    order = ["info", "low", "medium", "high", "critical"]
    for r in rels:
        sev = ESCALATION_EDGES.get(r, ("info", "", ""))[0]
        if order.index(sev) > order.index(worst):
            worst = sev
    return worst


def analyze(data: dict) -> list[Finding]:
    """Return Findings for each realistic principal -> crown-jewel escalation path."""
    g = IdentityGraph(data)
    findings: list[Finding] = []
    seen_sigs = set()
    for start in g.entry_principals():
        for path, rels in g.paths_to_crown_jewels(start):
            sig = tuple(path)
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            chain = []
            mitre = []
            for i, nid in enumerate(path):
                chain.append(_label(g, nid))
                if i < len(rels):
                    chain.append(f"--{rels[i]}-->")
                    tech = ESCALATION_EDGES.get(rels[i], ("", "", ""))[1]
                    if tech and tech not in mitre:
                        mitre.append(tech)
            sev = _path_severity(rels)
            target = path[-1]
            f = Finding(
                id="identity.escalation_path",
                title=f"Privilege-escalation path to {_label(g, target)}",
                severity=sev if sev != "info" else "medium",
                kind="vulnerability",
                confidence="high_confidence",
                validation="validated",   # graph-derived from authorized data == deterministic
                asset=_label(g, target),
                component=_label(g, start),
                evidence=" ".join(chain)[:400],
                description="A reachable chain of identity relationships lets a lower-privileged principal "
                            "reach a high-value target.",
                attack="Attacker who compromises the starting principal follows these edges (group membership, "
                       "role assumption, ACL abuse, delegation, sessions) to escalate/move laterally to the crown jewel.",
                patch="Break the chain: remove excessive group memberships/ACLs (WriteDacl/GenericAll), tier admin "
                      "accounts, restrict role assumption & delegation, and monitor high-value object ACLs.",
                cwe="CWE-269",
                owasp="A01:2021 Broken Access Control",
                mitre=mitre,
            )
            findings.append(f)
    # rank by severity then path length
    findings.sort(key=lambda x: (_SEV_W.get(x.severity, 0), len(x.evidence)), reverse=True)
    return findings


def load_and_analyze(path: str) -> list[Finding]:
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
    except Exception:
        return []
    return analyze(data)
