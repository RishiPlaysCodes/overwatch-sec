#!/usr/bin/env python3
"""
reporting/compare.py — baseline + retest diffing (spec §18).

Compare a new assessment against a prior report.json to show what changed:
new / fixed / persistent findings, and the risk-score delta. Findings are
matched by their stable fingerprint (id + asset + component + cve).
"""

from __future__ import annotations

import json


def _load(path: str) -> dict:
    with open(path, "r") as fh:
        return json.load(fh)


def _fps(report: dict) -> dict:
    """fingerprint -> minimal finding info, from a report.json."""
    out = {}
    for f in report.get("findings", []):
        fp = f.get("fingerprint") or f.get("id", "")
        out[fp] = {"title": f.get("title", ""), "severity": f.get("severity", "info"),
                   "asset": f.get("asset", ""), "id": f.get("id", "")}
    return out


def compare(old_report_path: str, new_assessment) -> dict:
    old = _load(old_report_path)
    old_fps = _fps(old)
    new_fps = {f.fingerprint(): {"title": f.title, "severity": f.severity,
                                 "asset": f.asset, "id": f.id}
               for f in new_assessment.findings}

    new_ids = set(new_fps) - set(old_fps)
    fixed_ids = set(old_fps) - set(new_fps)
    persistent_ids = set(old_fps) & set(new_fps)

    old_score = old.get("summary", {}).get("security_score")
    from .report import security_score
    new_score = security_score(new_assessment.findings)

    old_paths = len(old.get("attack_paths", []))
    new_paths = len(new_assessment.attack_paths)

    return {
        "new": [new_fps[i] for i in new_ids],
        "fixed": [old_fps[i] for i in fixed_ids],
        "persistent": [new_fps[i] for i in persistent_ids],
        "counts": {"new": len(new_ids), "fixed": len(fixed_ids), "persistent": len(persistent_ids)},
        "risk_score": {"old": old_score, "new": new_score,
                       "delta": (new_score - old_score) if isinstance(old_score, (int, float)) else None},
        "attack_paths": {"old": old_paths, "new": new_paths, "delta": new_paths - old_paths},
    }


def render(diff: dict) -> str:
    c = diff["counts"]
    L = ["ASSESSMENT COMPARISON (baseline vs current)", ""]
    L.append(f"  New vulnerabilities        : {c['new']}")
    L.append(f"  Fixed vulnerabilities      : {c['fixed']}")
    L.append(f"  Persistent vulnerabilities : {c['persistent']}")
    rs = diff["risk_score"]
    if rs["delta"] is not None:
        arrow = "improved" if rs["delta"] > 0 else "worsened" if rs["delta"] < 0 else "unchanged"
        L.append(f"  Security score             : {rs['old']} -> {rs['new']} ({arrow})")
    ap = diff["attack_paths"]
    L.append(f"  Attack paths               : {ap['old']} -> {ap['new']} (Δ{ap['delta']})")
    if diff["new"]:
        L.append("\n  NEW:")
        for f in diff["new"][:15]:
            L.append(f"    + [{f['severity'].upper()}] {f['title']} ({f['asset']})")
    if diff["fixed"]:
        L.append("\n  FIXED:")
        for f in diff["fixed"][:15]:
            L.append(f"    - [{f['severity'].upper()}] {f['title']} ({f['asset']})")
    return "\n".join(L)
