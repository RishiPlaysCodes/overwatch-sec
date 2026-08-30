#!/usr/bin/env python3
"""
reporting/sarif.py — SARIF 2.1.0 export + CI gating.

SARIF (Static Analysis Results Interchange Format) is what GitHub Code Scanning
and most CI dashboards ingest. Exporting to SARIF lets overwatch results appear
as annotations on PRs / in the Security tab.

Also provides `gate()` — evaluates a fail threshold (severity / KEV / new
findings vs a baseline) and returns an exit code so CI can fail the build.
"""

from __future__ import annotations

import json

_SARIF_LEVEL = {  # our severity -> SARIF level
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _rules(findings) -> list:
    seen, rules = {}, []
    for f in findings:
        if f.id in seen:
            continue
        seen[f.id] = True
        rules.append({
            "id": f.id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description or f.title},
            "help": {"text": (f.patch or "See remediation.")},
            "properties": {
                "security-severity": _security_severity(f),
                "cwe": f.cwe, "owasp": f.owasp, "tags": ["security"] + (f.mitre or []),
            },
        })
    return rules


def _security_severity(f) -> str:
    """GitHub uses a 0-10 numeric string; prefer CVSS, else map from severity."""
    if f.cvss is not None:
        return str(f.cvss)
    return {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "3.0", "info": "0.0"}.get(f.severity, "0.0")


def to_sarif(assessment) -> dict:
    findings = assessment.findings
    results = []
    for f in findings:
        msg = f.description or f.title
        if f.attack:
            msg += f"  Attack: {f.attack}"
        results.append({
            "ruleId": f.id,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title} — {f.evidence}"[:1000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.asset or assessment.target)},
                }
            }],
            "properties": {
                "severity": f.severity, "confidence": f.confidence,
                "validation": f.validation, "status": f.status,
                "cve": f.cve, "kev": f.kev, "mitre": f.mitre,
                "fingerprint": f.fingerprint(),
            },
            "partialFingerprints": {"overwatch/v1": f.fingerprint()},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "overwatch",
                "informationUri": "https://github.com/RishiPlaysCodes/script-test-case",
                "version": "4.0.0",
                "rules": _rules(findings),
            }},
            "results": results,
            "properties": {
                "profile": assessment.profile, "mode": assessment.mode,
                "target": assessment.target, "kind": assessment.kind,
            },
        }],
    }


def _uri(asset: str) -> str:
    if asset.startswith(("http://", "https://")):
        return asset
    return "asset://" + asset


def write_sarif(assessment, path: str) -> str:
    with open(path, "w") as fh:
        json.dump(to_sarif(assessment), fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# CI gating
# ---------------------------------------------------------------------------
def gate(assessment, fail_on: str | None = None, fail_on_kev: bool = False,
         fail_on_new: bool = False, compare_diff: dict | None = None) -> tuple[int, str]:
    """
    Return (exit_code, reason). Exit 0 = pass; 1 = gate tripped. Only ACTIVE
    findings (not false_positive/fixed/accepted_risk) count.
    """
    from .report import _active
    active = _active(assessment.findings)
    reasons = []

    if fail_on:
        threshold = _SEV_RANK.get(fail_on.lower(), 99)
        hit = [f for f in active if _SEV_RANK.get(f.severity, 9) <= threshold]
        if hit:
            reasons.append(f"{len(hit)} finding(s) at severity >= {fail_on}")

    if fail_on_kev and any(f.kev for f in active):
        n = sum(1 for f in active if f.kev)
        reasons.append(f"{n} actively-exploited (CISA KEV) finding(s)")

    if fail_on_new and compare_diff is not None:
        n = compare_diff.get("counts", {}).get("new", 0)
        if n:
            reasons.append(f"{n} new finding(s) vs baseline")

    if reasons:
        return 1, "CI gate FAILED: " + "; ".join(reasons)
    return 0, "CI gate passed"
