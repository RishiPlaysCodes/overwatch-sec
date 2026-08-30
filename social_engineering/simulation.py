#!/usr/bin/env python3
"""
social_engineering/simulation.py — analyze an authorized awareness campaign.

Input (JSON) — the RESULTS of a sanctioned simulation you already ran:
{
  "campaign": "Q3 phishing awareness",
  "authorized_by": "CISO ticket SEC-1234",
  "sent": 500,
  "opened": 240,
  "clicked": 88,
  "submitted_dummy_credentials": 31,   # DUMMY creds only; a COUNT, never values
  "reported": 145,
  "mfa_prompted": 31,
  "mfa_denied": 27,
  "policy": {"has_reporting_button": true, "training_current_pct": 62,
             "mfa_enforced": true, "phishing_policy_documented": false}
}

Output: human-risk metrics + Findings (kind=security_weakness) for weak spots.
No campaign is created or sent; no real credential is ever handled.
"""

from __future__ import annotations

import json

from core.findings import Finding


def _pct(n, d):
    return round(100 * n / d) if d else 0


def _f(fid, title, severity, evidence, attack, patch):
    return Finding(id=fid, title=title, severity=severity, kind="security_weakness",
                   confidence="high_confidence", validation="validated",
                   asset="human-layer", evidence=evidence[:300], description=title,
                   attack=attack, patch=patch, cwe="CWE-1039",
                   owasp="Human Risk / Security Awareness", mitre=["T1566"])  # Phishing


def analyze(data: dict) -> dict:
    sent = int(data.get("sent", 0) or 0)
    opened = int(data.get("opened", 0) or 0)
    clicked = int(data.get("clicked", 0) or 0)
    submitted = int(data.get("submitted_dummy_credentials", 0) or 0)
    reported = int(data.get("reported", 0) or 0)
    mfa_prompted = int(data.get("mfa_prompted", 0) or 0)
    mfa_denied = int(data.get("mfa_denied", 0) or 0)
    policy = data.get("policy", {}) or {}

    metrics = {
        "authorized_by": data.get("authorized_by", "UNSPECIFIED"),
        "sent": sent,
        "open_rate": _pct(opened, sent),
        "click_rate": _pct(clicked, sent),
        "credential_submission_rate": _pct(submitted, sent),  # dummy-cred exercise only
        "reporting_rate": _pct(reported, sent),
        "mfa_resilience": _pct(mfa_denied, mfa_prompted),
    }
    # human-risk score (higher = worse): weighted click/submit minus reporting credit
    risk = min(100, round(metrics["click_rate"] * 0.6 + metrics["credential_submission_rate"] * 1.2
                          - metrics["reporting_rate"] * 0.3 + 20))
    metrics["human_risk_score"] = max(0, risk)

    findings = []
    if metrics["click_rate"] >= 15:
        findings.append(_f("se.high_click_rate", "High phishing click rate",
                           "high" if metrics["click_rate"] >= 30 else "medium",
                           f"click rate {metrics['click_rate']}% ({clicked}/{sent})",
                           "A large fraction of staff click simulated lures; a real campaign would gain "
                           "initial footholds via phished users.",
                           "Targeted awareness training for clickers; simulate regularly; reduce email "
                           "attack surface (link isolation, attachment sandboxing)."))
    if metrics["credential_submission_rate"] >= 5:
        findings.append(_f("se.credential_submission", "Users submitted (dummy) credentials",
                           "high",
                           f"submission rate {metrics['credential_submission_rate']}% (dummy creds; counts only)",
                           "Users enter credentials on lure pages — real phishing would harvest valid creds "
                           "for account takeover.",
                           "Enforce phishing-resistant MFA (FIDO2), train on credential-entry red flags, and "
                           "deploy known-good login domains + password-manager autofill cues."))
    if metrics["reporting_rate"] < 30:
        findings.append(_f("se.low_reporting", "Low phishing reporting rate", "medium",
                           f"reporting rate {metrics['reporting_rate']}% ({reported}/{sent})",
                           "Few users report suspicious mail, so real attacks go unnoticed by the SOC longer.",
                           "Add a one-click report button, reward reporting, and set an SLA for triage."))
    if mfa_prompted and metrics["mfa_resilience"] < 80:
        findings.append(_f("se.mfa_fatigue", "Weak MFA-prompt resilience", "medium",
                           f"MFA-denied {metrics['mfa_resilience']}% of prompts",
                           "Users approve unexpected MFA prompts (MFA fatigue), enabling push-bombing attacks.",
                           "Enable number-matching/context in MFA, cap prompts, and train on unsolicited prompts."))
    # policy gaps
    gaps = []
    if not policy.get("has_reporting_button"):
        gaps.append("no one-click report button")
    if not policy.get("mfa_enforced"):
        gaps.append("MFA not enforced org-wide")
    if not policy.get("phishing_policy_documented"):
        gaps.append("no documented phishing policy")
    tc = policy.get("training_current_pct")
    if isinstance(tc, (int, float)) and tc < 80:
        gaps.append(f"awareness training only {tc}% current")
    if gaps:
        findings.append(_f("se.policy_gap", "Security-awareness policy gaps", "low",
                           "; ".join(gaps),
                           "Missing policy/controls leave the human layer under-defended and inconsistent.",
                           "Document a phishing policy, enforce MFA, deploy a report button, and reach "
                           ">=80% current training."))
    return {"metrics": metrics, "findings": findings}


def load_and_analyze(path: str) -> dict:
    try:
        with open(path, "r", errors="ignore") as fh:
            data = json.load(fh)
    except Exception:
        return {"metrics": {}, "findings": []}
    return analyze(data)


def render(result: dict) -> str:
    m = result.get("metrics", {})
    if not m:
        return "SOCIAL-ENGINEERING SIMULATION\n  (no campaign data)"
    L = ["SOCIAL-ENGINEERING SIMULATION (authorized awareness exercise)", ""]
    L.append(f"  Authorized by     : {m.get('authorized_by')}")
    L.append(f"  Human risk score  : {m.get('human_risk_score')}/100")
    L.append(f"  Click rate        : {m.get('click_rate')}%")
    L.append(f"  Cred submission   : {m.get('credential_submission_rate')}%  (dummy creds; counts only)")
    L.append(f"  Reporting rate    : {m.get('reporting_rate')}%")
    L.append(f"  MFA resilience    : {m.get('mfa_resilience')}%")
    L.append("  Note: analysis of an authorized simulation only — no campaign was sent, no real credentials handled.")
    return "\n".join(L)
