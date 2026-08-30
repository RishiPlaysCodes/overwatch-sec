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
    Correlate findings into attack paths. Backed by the graph engine
    (attack_paths.graph) which enumerates real Internet->objective paths with
    multi-asset (lateral) chaining. This function preserves the historical
    return contract used by reporting and tests.
    """
    from . import graph
    return graph.build_paths(findings, target)


def overall_risk(paths: list[dict]) -> float:
    return max([p["risk_score"] for p in paths], default=0.0)
