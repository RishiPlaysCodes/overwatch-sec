#!/usr/bin/env python3
"""
attack_paths/graph.py — a real node/edge attack-path graph.

Phase 2 upgrade over the heuristic per-asset ordering: build an actual directed
graph and enumerate paths from the internet entry point, through findings, to
"crown-jewel" objectives (data, credentials, account takeover, host access).
Multi-asset chaining is supported when a finding yields credentials/pivots.

Node kinds:  entry (Internet) | asset | finding | objective
Edges:       entry->asset (exposure), asset->finding (has),
             finding->objective (grants), finding->finding (chains on an asset),
             objective(credentials)->asset (enables lateral movement / pivot)

Everything is deterministic and stdlib-only. `build_paths()` keeps the old
report/test contract (asset, entry, length, risk_score, steps, chain) and adds
`objective`, so existing reporting and tests keep working.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .mitre import TACTIC_ORDER, tactic_of

# ---------------------------------------------------------------------------
# What does a finding get an attacker? (finding-id prefix -> objective, criticality 1..5)
# Objectives that yield credentials/accounts can pivot to OTHER assets (lateral).
# ---------------------------------------------------------------------------
OBJECTIVES = {
    "web.sqli":                 ("Database read/*write* access", 5, True),
    "web.cve":                  ("Application compromise", 5, True),
    "network.exploit_known":    ("Service compromise (public exploit)", 5, True),
    "network.vuln_service":     ("Service compromise", 4, True),
    "web.fileupload":           ("Remote code execution (web shell)", 5, True),
    "web.xss":                  ("Victim session / account takeover", 3, False),
    "recon.subdomain_takeover": ("Subdomain control (phishing/cookie theft)", 4, False),
    "code.secret":              ("Leaked credentials", 5, True),
    "recon.js_secret":          ("Leaked credentials", 4, True),
    "mobile.secrets":           ("Leaked credentials", 4, True),
    "cloud.iam_wildcard":       ("Cloud account takeover", 5, True),
    "cloud.no_mfa":             ("Cloud account takeover", 5, True),
    "cloud.public_bucket":      ("Sensitive data exposure", 4, False),
    "cloud.unencrypted":        ("Sensitive data exposure", 3, False),
    "cloud.public_ip":          ("Exposed compute foothold", 3, True),
    "cloud.open_sg":            ("Exposed service foothold", 3, True),
    "container.cve":            ("Container compromise", 4, True),
    "container.misconfig":      ("Container escape to host", 4, True),
    "recon.exposed_panel":      ("Admin access (if creds obtained)", 3, True),
    "web.cookie":               ("Session hijack", 3, False),
    "identity.escalation_path": ("Privilege escalation / domain or account compromise", 5, True),
    "api.no_auth":              ("Unauthenticated API data/function access", 4, True),
    "api.graphql_introspection":("GraphQL schema / data exposure", 3, False),
    "k8s.privileged":           ("Container escape to node", 5, True),
    "k8s.hostpath":             ("Host filesystem access / node takeover", 5, True),
    "k8s.rbac_wildcard":        ("Cluster-admin takeover", 5, True),
    "threat.malicious_process": ("Active compromise (host)", 5, True),
    "threat.c2_connection":     ("Active compromise (C2)", 5, True),
}


def _objective_for(fid: str):
    if fid in OBJECTIVES:
        return OBJECTIVES[fid]
    for k, v in OBJECTIVES.items():
        if fid.startswith(k):
            return v
    return None


_SEV_W = {"critical": 40, "high": 30, "medium": 15, "low": 5, "info": 1}


@dataclass
class Node:
    id: str
    kind: str            # entry|asset|finding|objective
    label: str
    data: dict = field(default_factory=dict)


class Graph:
    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: list[tuple[str, str, str]] = []   # (src, dst, relation)
        self._adj: dict[str, list[tuple[str, str]]] = {}

    def add_node(self, node: Node):
        self.nodes.setdefault(node.id, node)
        self._adj.setdefault(node.id, [])

    def add_edge(self, src: str, dst: str, rel: str):
        if (src, dst, rel) not in self.edges:
            self.edges.append((src, dst, rel))
            self._adj.setdefault(src, []).append((dst, rel))

    # enumerate simple paths entry -> objective (bounded)
    def paths_to_objectives(self, entry: str, max_len: int = 8, max_paths: int = 200):
        results = []

        def dfs(node_id, path, seen):
            if len(path) > max_len or len(results) >= max_paths:
                return
            node = self.nodes[node_id]
            if node.kind == "objective" and len(path) > 1:
                results.append(list(path))
                # keep exploring for longer chains too, but don't revisit
            for dst, _rel in self._adj.get(node_id, []):
                if dst in seen:
                    continue
                seen.add(dst)
                path.append(dst)
                dfs(dst, path, seen)
                path.pop()
                seen.discard(dst)

        dfs(entry, [entry], {entry})
        return results


def build(findings, target: str) -> Graph:
    g = Graph()
    g.add_node(Node("internet", "entry", "Internet"))

    # asset nodes
    assets = {}
    for f in findings:
        a = f.asset or target
        if a not in assets:
            nid = f"asset:{a}"
            assets[a] = nid
            g.add_node(Node(nid, "asset", a))
            g.add_edge("internet", nid, "exposure")

    # finding + objective nodes
    for i, f in enumerate(findings):
        a = f.asset or target
        fid_node = f"finding:{i}:{f.id}"
        g.add_node(Node(fid_node, "finding", f.title,
                        {"severity": f.severity, "kev": f.kev, "cvss": f.cvss,
                         "id": f.id, "mitre": list(f.mitre), "tactic": tactic_of(f.id)}))
        g.add_edge(assets[a], fid_node, "has")
        obj = _objective_for(f.id)
        if obj:
            name, crit, pivots = obj
            oid = f"objective:{name}"
            g.add_node(Node(oid, "objective", name, {"criticality": crit, "pivots": pivots}))
            g.add_edge(fid_node, oid, "grants")
            # lateral movement: a credential/account objective can pivot to other assets
            if pivots:
                for other_a, other_nid in assets.items():
                    if other_a != a:
                        g.add_edge(oid, other_nid, "lateral")
    return g


def _score_path(g: Graph, path: list[str]) -> float:
    findings = [g.nodes[n] for n in path if g.nodes[n].kind == "finding"]
    objectives = [g.nodes[n] for n in path if g.nodes[n].kind == "objective"]
    if not findings:
        return 0.0
    base = max(_SEV_W.get(f.data.get("severity", "info"), 1) for f in findings)
    kev_bonus = 25 if any(f.data.get("kev") for f in findings) else 0
    cvss_bonus = max([(f.data.get("cvss") or 0) for f in findings]) * 1.5
    crit_bonus = max([o.data.get("criticality", 0) for o in objectives], default=0) * 5
    lateral_bonus = 10 if any(g.nodes[a].kind == "asset" for a in path[2:]) else 0  # reached >1 asset
    chain_bonus = min(len(findings) * 3, 15)
    return round(min(base + kev_bonus + cvss_bonus + crit_bonus + lateral_bonus + chain_bonus, 100), 1)


def build_paths(findings, target: str) -> list[dict]:
    """
    Report/test-compatible view. Returns entry->objective paths, richest first,
    plus per-asset single-step observations for findings without an objective.
    Keys: asset, entry(bool), length, risk_score, steps, chain, objective.
    """
    g = build(findings, target)
    raw = g.paths_to_objectives("internet")

    out = []
    seen_sigs = set()
    for path in raw:
        fnodes = [g.nodes[n] for n in path if g.nodes[n].kind == "finding"]
        onodes = [g.nodes[n] for n in path if g.nodes[n].kind == "objective"]
        anodes = [g.nodes[n] for n in path if g.nodes[n].kind == "asset"]
        if not fnodes:
            continue
        sig = tuple(n for n in path)
        if sig in seen_sigs:
            continue
        seen_sigs.add(sig)
        steps = [{"tactic": fn.data.get("tactic", ""), "technique": (fn.data.get("mitre") or [""])[0],
                  "finding": fn.label, "id": fn.data.get("id"), "severity": fn.data.get("severity"),
                  "kev": fn.data.get("kev")} for fn in fnodes]
        chain_labels = ["Internet"]
        for n in path[1:]:
            node = g.nodes[n]
            if node.kind == "asset":
                chain_labels.append(f"asset: {node.label}")
            elif node.kind == "finding":
                chain_labels.append(f"{node.data.get('tactic','')}: {node.label}")
            elif node.kind == "objective":
                chain_labels.append(f"🎯 {node.label}")
        out.append({
            "asset": anodes[0].label if anodes else target,
            "entry": True,
            "length": len(fnodes),
            "risk_score": _score_path(g, path),
            "steps": steps,
            "chain": " -> ".join(chain_labels),
            "objective": onodes[-1].label if onodes else "",
            "multi_asset": len(anodes) > 1,
        })

    # per-asset fallback observations for findings that reached no objective
    covered_assets = {p["asset"] for p in out}
    by_asset = {}
    for f in findings:
        by_asset.setdefault(f.asset or target, []).append(f)
    for asset, fs in by_asset.items():
        if asset in covered_assets:
            continue
        ordered = sorted(fs, key=lambda f: TACTIC_ORDER.index(tactic_of(f.id))
                         if tactic_of(f.id) in TACTIC_ORDER else 99)
        steps = [{"tactic": tactic_of(f.id), "technique": (f.mitre or [""])[0],
                  "finding": f.title, "id": f.id, "severity": f.severity, "kev": f.kev} for f in ordered]
        chain = ["Internet", f"asset: {asset}"] + [f"{s['tactic']}: {s['finding']}" for s in steps]
        base = max(_SEV_W.get(f.severity, 1) for f in fs)
        kev = 25 if any(f.kev for f in fs) else 0
        cvss = max([(f.cvss or 0) for f in fs]) * 1.5
        out.append({"asset": asset, "entry": any(s["tactic"] in ("initial-access", "execution", "reconnaissance")
                                                  for s in steps),
                    "length": len(steps), "risk_score": round(min(base + kev + cvss, 100), 1),
                    "steps": steps, "chain": " -> ".join(chain), "objective": "", "multi_asset": False})

    out.sort(key=lambda p: (0 if p.get("objective") else 1, -p["risk_score"], -p["length"]))
    return out


def to_mermaid(findings, target: str, max_edges: int = 60) -> str:
    """Render the attack graph as a Mermaid flowchart (embeds in Markdown/HTML)."""
    g = build(findings, target)
    lines = ["flowchart LR"]

    def nid(x):
        return "n" + str(abs(hash(x)) % 10_000_000)

    def esc(s):
        return s.replace('"', "'")[:48]

    shape = {"entry": ('(["', '"])'), "asset": ('["', '"]'), "finding": ('("', '")'),
             "objective": ('{{"', '"}}')}
    drawn = 0
    for src, dst, rel in g.edges:
        if drawn >= max_edges:
            break
        sn, dn = g.nodes[src], g.nodes[dst]
        so, sc = shape[sn.kind]
        do, dc = shape[dn.kind]
        lines.append(f'  {nid(src)}{so}{esc(sn.label)}{sc} -->|{rel}| {nid(dst)}{do}{esc(dn.label)}{dc}')
        drawn += 1
    lines.append("  classDef obj fill:#8e44ad,color:#fff;")
    return "\n".join(lines)


def overall_risk(paths: list[dict]) -> float:
    return max([p["risk_score"] for p in paths], default=0.0)
