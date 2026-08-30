#!/usr/bin/env python3
"""
purple/verification.py — map executed test activity to expected telemetry and
correlate with defensive detections.

Inputs:
  findings   — the assessment findings (each with id / mitre / validation)
  telemetry  — optional dict from a SIEM/EDR/IDS export you provide:
               {
                 "detections": [
                    {"technique": "T1190", "rule": "WAF-SQLi", "alerted": true,
                     "latency_seconds": 12, "source": "waf"},
                    {"signature": "web.header", "alerted": false}
                 ]
               }
               A detection matches a technique by ATT&CK id OR by finding-id/prefix.

Output: a list of TechniqueVerification rows + a coverage summary. When no
telemetry is supplied, everything is reported as an unverified DETECTION GAP
(honest default — absence of data is not evidence of detection).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from attack_paths.mitre import technique_for

# expected telemetry per finding-id prefix (what a defender SHOULD see)
EXPECTED_TELEMETRY = {
    "web.sqli": "WAF/app logs: anomalous query params; DB error spikes",
    "web.xss": "WAF/app logs: script-like payloads in parameters",
    "web.fileupload": "app logs: unusual file uploads; AV/file-scan events",
    "web.header": "proxy/app response-header audit (config drift)",
    "web.cookie": "app config audit; session-cookie policy monitoring",
    "api.cors": "API gateway logs: cross-origin requests with credentials",
    "api.no_auth": "API gateway/auth logs: unauthenticated 2xx to protected routes",
    "network.exposed_service": "netflow/firewall: connections to the exposed port",
    "network.vuln_service": "IDS/IPS signature for the service vuln",
    "network.exploit_known": "IDS/EDR: exploitation attempt for the CVE",
    "recon.subdomain": "DNS logs / passive DNS: enumeration bursts",
    "recon.dir_listing": "web logs: directory-index responses",
    "identity.escalation_path": "IdP/AD audit: group/role/ACL changes; risky assumptions",
    "threat.malicious_process": "EDR: process-creation + known-bad hash alert",
    "threat.c2_connection": "EDR/NDR: beaconing to known-malicious infra",
    "threat.persistence": "EDR: new scheduled task/service; autoruns",
    "k8s.privileged": "K8s audit/admission: privileged pod creation",
    "cloud.iam_wildcard": "CloudTrail/Activity: wildcard policy attach",
}

# suggested detection when there's a gap
RECOMMENDED_RULE = {
    "web.sqli": "Alert on SQL error patterns + WAF SQLi signature on the endpoint",
    "web.xss": "WAF rule for script payloads; CSP violation reporting",
    "api.no_auth": "Alert on 2xx to auth-required routes without a valid token",
    "network.exploit_known": "Deploy/enable IDS signature for the matched CVE",
    "identity.escalation_path": "Alert on sensitive group/ACL changes and risky role assumption",
    "threat.c2_connection": "Block + alert on egress to threat-intel indicators",
    "k8s.privileged": "Admission policy to deny privileged pods + audit alert",
}


@dataclass
class TechniqueVerification:
    finding_id: str
    technique: str
    tactic: str
    expected_telemetry: str
    detected: bool
    alert_latency: float | None
    detection_rule: str
    detection_gap: bool
    recommendation: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _expected_for(fid: str) -> str:
    if fid in EXPECTED_TELEMETRY:
        return EXPECTED_TELEMETRY[fid]
    for k, v in EXPECTED_TELEMETRY.items():
        if fid.startswith(k):
            return v
    return "generic security telemetry (define an expected-telemetry mapping)"


def _recommend(fid: str) -> str:
    for k, v in RECOMMENDED_RULE.items():
        if fid == k or fid.startswith(k):
            return v
    return "Add a detection rule for the expected telemetry above."


def _match_detection(fid: str, technique: str, detections: list) -> dict | None:
    for d in detections or []:
        if technique and d.get("technique") and d["technique"].upper() == technique.upper():
            return d
        sig = d.get("signature") or d.get("finding_id") or ""
        if sig and (fid == sig or fid.startswith(sig)):
            return d
    return None


def verify(findings, telemetry: dict | None = None) -> dict:
    """
    Correlate executed test activity with defensive detections.
    Only findings that represent real *activity* worth detecting are considered
    (skip pure config observations already covered as audit).
    """
    detections = (telemetry or {}).get("detections", [])
    rows: list[TechniqueVerification] = []
    seen = set()

    for f in findings:
        # skip states that were blocked/not-run — no test activity occurred
        if getattr(f, "validation", "") in ("blocked_by_policy", "blocked_by_scope",
                                            "blocked_by_authentication", "blocked_by_missing_dependency"):
            continue
        tech = technique_for(f.id)
        tid = tech[0] if tech else ""
        tactic = tech[2] if tech else ""
        key = (f.id, tid)
        if key in seen:
            continue
        seen.add(key)

        d = _match_detection(f.id, tid, detections)
        detected = bool(d and d.get("alerted", d.get("detected", False)))
        rule = (d or {}).get("rule", "") if d else ""
        latency = (d or {}).get("latency_seconds") if d else None
        gap = not detected
        rows.append(TechniqueVerification(
            finding_id=f.id, technique=tid, tactic=tactic,
            expected_telemetry=_expected_for(f.id),
            detected=detected, alert_latency=latency, detection_rule=rule,
            detection_gap=gap, recommendation=("" if detected else _recommend(f.id)),
        ))

    total = len(rows)
    detected = sum(1 for r in rows if r.detected)
    return {
        "rows": [r.to_dict() for r in rows],
        "summary": {
            "techniques_considered": total,
            "detected": detected,
            "gaps": total - detected,
            "detection_rate": (round(100 * detected / total) if total else 0),
            "telemetry_provided": bool(detections),
            "note": ("No telemetry export supplied — all activity is reported as an "
                     "unverified detection gap (absence of data is not proof of detection)."
                     if not detections else
                     "Detections correlated from the supplied SIEM/EDR/IDS export."),
        },
    }


def load_and_verify(findings, telemetry_path: str | None):
    tel = None
    if telemetry_path:
        try:
            import json
            with open(telemetry_path) as fh:
                tel = json.load(fh)
        except Exception:
            tel = None
    return verify(findings, tel)


def render(result: dict) -> str:
    s = result["summary"]
    L = ["DETECTION VERIFICATION (purple team)", ""]
    L.append(f"  Techniques considered : {s['techniques_considered']}")
    L.append(f"  Detected              : {s['detected']}")
    L.append(f"  Detection gaps        : {s['gaps']}")
    L.append(f"  Detection rate        : {s['detection_rate']}%")
    L.append(f"  {s['note']}")
    gaps = [r for r in result["rows"] if r["detection_gap"]]
    if gaps:
        L.append("\n  GAPS (no detection observed):")
        for r in gaps[:12]:
            L.append(f"    - [{r['technique'] or 'n/a'}] {r['finding_id']} — expected: {r['expected_telemetry']}")
            if r["recommendation"]:
                L.append(f"        recommend: {r['recommendation']}")
    return "\n".join(L)
