#!/usr/bin/env python3
"""
connectors/bloodhound.py — BloodHound export -> overwatch identity graph.

Accepts either:
  - a simple {"nodes":[...], "edges":[...]} export, or
  - BloodHound-style {"data":[{"Properties":{"name":..}, "Aces":[...]}], "meta":{...}}

Produces the identity-graph schema consumed by attack_paths.identity:
    {"nodes":[{"id","type","tier","high_value","label"}],
     "edges":[{"src","dst","rel"}]}

Pure parser — never talks to a live directory.
"""

from __future__ import annotations

_HV_KEYWORDS = ("domain admins", "enterprise admins", "administrators", "domain controllers")


def looks_like(raw) -> bool:
    if isinstance(raw, dict):
        if "nodes" in raw and "edges" in raw:
            return True
        if "meta" in raw and "data" in raw:
            return True
        if "Aces" in str(raw)[:500] or "ObjectIdentifier" in str(raw)[:500]:
            return True
    return False


def _tier(label: str, props: dict) -> str:
    name = (label or "").lower()
    if props.get("admincount") or any(k in name for k in _HV_KEYWORDS):
        return "high"
    return "low"


def to_identity(raw) -> dict:
    # already in our simple format
    if isinstance(raw, dict) and "nodes" in raw and "edges" in raw:
        return raw

    nodes, edges = [], []
    seen = set()

    def add_node(nid, ntype, label=None, high=False, tier="low"):
        if nid and nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "type": ntype, "label": label or nid,
                          "tier": tier, "high_value": high})

    data = raw.get("data", []) if isinstance(raw, dict) else raw
    meta_type = (raw.get("meta", {}) or {}).get("type", "") if isinstance(raw, dict) else ""

    for obj in (data or []):
        props = obj.get("Properties", obj.get("properties", {})) or {}
        name = props.get("name") or obj.get("ObjectIdentifier") or obj.get("id")
        ntype = (obj.get("type") or meta_type or "user").rstrip("s").lower()
        high = bool(props.get("highvalue")) or ntype in ("domain", "ou")
        add_node(name, ntype, name, high, _tier(name, props))
        # ACEs / edges
        for ace in obj.get("Aces", obj.get("aces", [])) or []:
            principal = ace.get("PrincipalSID") or ace.get("principal")
            right = ace.get("RightName") or ace.get("right") or "GenericAll"
            if principal and name:
                add_node(principal, "user", principal)
                edges.append({"src": principal, "dst": name, "rel": right})
        # explicit edges array on the object
        for e in obj.get("edges", []) or []:
            edges.append({"src": e.get("src"), "dst": e.get("dst"), "rel": e.get("rel", "MemberOf")})

    # top-level edges too
    for e in (raw.get("edges", []) if isinstance(raw, dict) else []):
        edges.append({"src": e.get("src"), "dst": e.get("dst"), "rel": e.get("rel", "MemberOf")})

    return {"nodes": nodes, "edges": [e for e in edges if e.get("src") and e.get("dst")]}
