#!/usr/bin/env python3
"""
validation/confidence.py — confidence & validation-state helpers.

Keeps the vocabulary consistent and provides small, testable transitions used
by the validator (e.g. a safe confirmation bumps confidence toward CONFIRMED).
"""

from __future__ import annotations

from core.findings import CONFIDENCE_LEVELS, VALIDATION_STATES

_CONF_RANK = {c: i for i, c in enumerate(reversed(CONFIDENCE_LEVELS))}  # confirmed=highest


def bump_confidence(current: str, floor: str) -> str:
    """Return the stronger of current vs floor confidence."""
    if current not in _CONF_RANK:
        return floor
    return current if _CONF_RANK.get(current, 0) >= _CONF_RANK.get(floor, 0) else floor


def mark_validated(finding, note: str = "") -> None:
    finding.validation = "validated"
    finding.confidence = "confirmed"
    if note:
        finding.evidence = (finding.evidence + f"  [validated: {note}]").strip()


def mark_not_exploitable(finding, note: str = "") -> None:
    finding.validation = "not_exploitable"
    finding.confidence = bump_confidence(finding.confidence, "high_confidence")
    if note:
        finding.evidence = (finding.evidence + f"  [checked: {note}]").strip()


def mark_manual(finding, note: str = "manual validation required") -> None:
    if finding.validation == "detected":
        finding.evidence = (finding.evidence + f"  [{note}]").strip()


def is_state(state: str) -> bool:
    return state in VALIDATION_STATES
