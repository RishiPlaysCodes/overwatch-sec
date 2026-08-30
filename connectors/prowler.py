#!/usr/bin/env python3
"""
connectors/prowler.py — Prowler (v3/v4) JSON -> overwatch findings/threat data.

Prowler emits a list of check results. We convert FAILing, security-relevant
checks into the threat_detection input shape where they map cleanly (risky IAM
keys, MFA gaps), and expose the raw failures via to_findings() for the report.
Pure parser (offline).
"""

from __future__ import annotations

from core.findings import Finding

_SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
            "informational": "info", "info": "info"}


def looks_like(raw) -> bool:
    if isinstance(raw, list) and raw and isinstance(raw[0], dict):
        keys = set(raw[0])
        return bool(keys & {"check_id", "CheckID", "status", "Status", "check_title"})
    return False


def _get(d, *names, default=""):
    for n in names:
        if n in d:
            return d[n]
    return default


def to_findings(raw) -> list:
    out = []
    for item in raw or []:
        status = str(_get(item, "status", "Status")).upper()
        if status not in ("FAIL", "FAILED"):
            continue
        sev = _SEV_MAP.get(str(_get(item, "severity", "Severity", default="medium")).lower(), "medium")
        cid = _get(item, "check_id", "CheckID", default="prowler.check")
        title = _get(item, "check_title", "CheckTitle", "check_id", default=cid)
        region = _get(item, "region", "Region")
        resource = _get(item, "resource_id", "ResourceId", "resource_uid")
        out.append(Finding(
            id=f"cloud.prowler.{cid}", title=title[:100], severity=sev,
            kind="misconfiguration", confidence="high_confidence", validation="validated",
            asset=str(resource or region or "cloud"),
            evidence=f"{cid} FAIL {('['+region+']') if region else ''} {resource}".strip()[:300],
            description=_get(item, "risk", "Risk", default=title)[:300],
            attack="Cloud misconfiguration flagged by Prowler; see the check's documentation.",
            patch=_get(item, "remediation_recommendation_text", "Remediation",
                       default="Apply the Prowler-recommended remediation.")[:300] or "See Prowler remediation.",
            owasp="Cloud: Security Misconfiguration", cwe="CWE-16",
        ))
    return out


# Note: Prowler results map to findings (see to_findings), not host telemetry.
