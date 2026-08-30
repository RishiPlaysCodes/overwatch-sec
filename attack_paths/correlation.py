#!/usr/bin/env python3
"""
attack_paths/correlation.py — turn a pile of findings into attack paths.

Rather than 50 unrelated findings, we chain them along the kill-chain (by MITRE
tactic) into candidate attack paths and score each path's risk. This is a
heuristic correlation (Phase 1) — it groups by asset and orders by tactic — and
is designed to be replaced/extended by a graph engine later.
"""

from __future__ import annotations

from .mitre import TACTIC_ORDER, tactic_of

# entry points that plausibly start a chain
_ENTRY_TACTICS = {"reconnaissance", "initial-access", "execution"}


def _risk_score(findings) -> float:
    """0..100 path risk from severity, KEV, CVSS, and chain length."""
    if not findings:
        return 0.0
    sev_weight = {"critical": 40, "high": 30, "medium": 15, "low": 5, "info": 1}
    base = max(sev_weight.get(f.severity, 1) for f in findings)
    kev_bonus = 25 if any(f.kev for f in findings) else 0
    cvss_bonus = max([(f.cvss or 0) for f in findings]) * 1.5
    chain_bonus = min(len(findings) * 4, 20)   # longer realistic chains = higher risk
    return round(min(base + kev_bonus + cvss_bonus + chain_bonus, 100), 1)


def build_paths(findings, target: str) -> list[dict]:
    """
    Group findings per asset and order them by kill-chain tactic to form paths.
    Only assets that have at least one 'entry' finding plus an escalation/impact
    finding produce a multi-step path; others become single-step observations.
    """
    by_asset: dict[str, list] = {}
    for f in findings:
        by_asset.setdefault(f.asset or target, []).append(f)

    paths = []
    for asset, fs in by_asset.items():
        # order by tactic position in the kill chain
        ordered = sorted(fs, key=lambda f: TACTIC_ORDER.index(tactic_of(f.id))
                         if tactic_of(f.id) in TACTIC_ORDER else 99)
        # de-dup consecutive identical tactics but keep highest severity per step
        steps = []
        for f in ordered:
            tac = tactic_of(f.id)
            steps.append({
                "tactic": tac,
                "technique": f.mitre[0] if f.mitre else "",
                "finding": f.title,
                "id": f.id,
                "severity": f.severity,
                "kev": f.kev,
                "asset": asset,
            })
        has_entry = any(s["tactic"] in _ENTRY_TACTICS for s in steps)
        # build a readable chain string
        chain = ["Internet"] + [f"{s['tactic']}: {s['finding']}" for s in steps]
        paths.append({
            "asset": asset,
            "entry": has_entry,
            "length": len(steps),
            "risk_score": _risk_score(fs),
            "steps": steps,
            "chain": " -> ".join(chain),
        })

    # rank: entry paths first, then by risk, then length
    paths.sort(key=lambda p: (0 if p["entry"] else 1, -p["risk_score"], -p["length"]))
    return paths


def overall_risk(paths: list[dict]) -> float:
    return max([p["risk_score"] for p in paths], default=0.0)
