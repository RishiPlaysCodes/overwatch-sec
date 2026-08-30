#!/usr/bin/env python3
"""
core/findings.py — the unified Finding model.

Every scanner (old or new) ultimately produces Findings. A Finding records not
just "what" but the *epistemics*: how sure are we (confidence), did we validate
it (validation state), and what's its lifecycle status (open / fixed / FP …).
This is what lets the platform avoid the classic "possible SQL injection" noise
and instead say DETECTED vs VALIDATED vs FALSE_POSITIVE.

Backwards compatible: the legacy scanners emit plain dicts
({severity,title,cwe,owasp,description,attack,patch,evidence}); `from_legacy`
lifts those into full Findings without changing the scanners.
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass, field, asdict

# ---- ordered vocabularies -------------------------------------------------
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# How exploitable / real is it?  (validation lifecycle)
VALIDATION_STATES = (
    "detected",                     # a signal was seen
    "likely",                       # multiple signals agree
    "validation_pending",           # queued for controlled validation
    "validated",                    # safely confirmed by a controlled check
    "not_validated",                # validation ran but did not confirm
    "exploitable",                  # confirmed exploitable (authorized validation only)
    "not_exploitable",              # checked, cannot be exploited in this context
    "false_positive",               # ruled out
    "manual_validation_required",   # needs a human (unsafe/complex to auto-verify)
    "blocked_by_policy",            # a validator exists but the policy forbids it
    "blocked_by_scope",             # target/asset out of authorized scope
    "blocked_by_authentication",    # needs credentials that weren't supplied
    "blocked_by_missing_dependency",# a required tool isn't installed
    "unknown",                      # could not determine
    "error",                        # validation errored
)

# validation states that mean "we tried/decided, don't just say 'detected'"
_TERMINAL_VALIDATION = {
    "validated", "not_validated", "exploitable", "not_exploitable", "false_positive",
    "manual_validation_required", "blocked_by_policy", "blocked_by_scope",
    "blocked_by_authentication", "blocked_by_missing_dependency", "error",
}

# How confident are we in the detection itself?  (section 17)
CONFIDENCE_LEVELS = (
    "confirmed", "high_confidence", "medium_confidence", "low_confidence", "informational",
)

# Lifecycle for tracking across scans  (section 17/18)
STATUSES = (
    "open", "validated", "false_positive", "accepted_risk", "fixed", "retest_required",
)

# Distinguish issue classes  (section 7/8)
KINDS = (
    "vulnerability", "misconfiguration", "security_weakness",
    "threat_indicator", "active_compromise_indicator", "info",
)


@dataclass
class Finding:
    # identity / classification
    id: str                      # KB id or scanner-specific id (e.g. "web.sqli")
    title: str
    severity: str = "info"       # critical|high|medium|low|info
    kind: str = "vulnerability"  # see KINDS
    # epistemics
    confidence: str = "medium_confidence"
    validation: str = "detected"
    status: str = "open"
    # context
    asset: str = ""              # host/url/file/resource the finding is on
    component: str = ""          # affected component/param/service
    evidence: str = ""           # safe, redacted evidence
    detection_method: str = ""   # which tool/check produced it
    # explanation (from the knowledgebase)
    description: str = ""
    attack: str = ""             # attack scenario
    patch: str = ""              # remediation
    # intelligence mappings
    cwe: str = "N/A"
    owasp: str = "N/A"
    cve: str = ""
    cvss: float | None = None
    kev: bool = False            # CISA Known-Exploited
    mitre: list[str] = field(default_factory=list)   # ATT&CK technique ids
    capec: list[str] = field(default_factory=list)   # CAPEC attack-pattern ids
    root_cause: str = ""         # underlying cause (professional finding format)
    references: list[str] = field(default_factory=list)
    # bookkeeping
    profile: str = ""
    tags: list[str] = field(default_factory=list)
    # structured validation evidence (populated by the validation engine)
    validation_evidence: dict = field(default_factory=dict)  # {tool,tool_version,test,reason,
                                                              #  timestamp,request,response,status}

    def set_validation(self, state: str, *, tool: str = "", tool_version: str = "",
                       test: str = "", reason: str = "", detail: str = "",
                       confidence: str | None = None) -> None:
        """Record a validation outcome with structured, timestamped evidence."""
        import time
        self.validation = state
        if confidence:
            self.confidence = confidence
        ev = {"tool": tool, "tool_version": tool_version, "test": test, "reason": reason,
              "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        ev = {k: v for k, v in ev.items() if v}
        self.validation_evidence.update(ev)
        if detail:
            self.evidence = (self.evidence + f"  [{state}: {detail}]").strip()

    def fingerprint(self) -> str:
        """Stable id for baseline/retest comparison (ignores volatile evidence)."""
        basis = f"{self.id}|{self.asset}|{self.component}|{self.cve}".lower()
        return hashlib.sha1(basis.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d

    # ---- normalization ----------------------------------------------------
    @staticmethod
    def _norm_sev(s: str) -> str:
        s = (s or "info").lower()
        return s if s in SEVERITY_ORDER else "info"

    @classmethod
    def from_legacy(cls, d: dict, asset: str = "", profile: str = "") -> "Finding":
        """Lift a legacy scanner dict into a Finding, inferring epistemics."""
        ev = d.get("evidence", "")
        kev = "CISA KEV" in ev or bool(d.get("kev"))
        # infer confidence/validation from the legacy evidence text
        conf = "medium_confidence"
        val = "detected"
        low = ev.lower()
        if kev or "confirmed" in low or "validated" in low:
            conf, val = "high_confidence", "likely"
        if d.get("id", "").startswith(("recon.subdomain", "network.exposed", "web.header",
                                       "web.infoleak", "recon.waf")):
            conf = conf if conf != "medium_confidence" else "high_confidence"
        kind = "misconfiguration" if "header" in d.get("id", "") or "misconfig" in d.get("id", "") \
            else "vulnerability"
        if d.get("severity") == "info":
            kind = "info"
        cvss = None
        m = None
        # pull a cvss out of "CVSS 9.8" style evidence
        import re
        mm = re.search(r"CVSS\s+([0-9]+(?:\.[0-9])?)", ev)
        if mm:
            try:
                cvss = float(mm.group(1))
            except ValueError:
                cvss = None
        cve_m = re.search(r"CVE-\d{4}-\d{4,7}", ev, re.I)
        return cls(
            id=d.get("id", "unknown"),
            title=d.get("title", d.get("id", "finding")),
            severity=cls._norm_sev(d.get("severity")),
            kind=kind,
            confidence=conf,
            validation=val,
            asset=asset or d.get("asset", ""),
            component=d.get("component", ""),
            evidence=ev,
            detection_method=d.get("detection_method", ""),
            description=d.get("description", ""),
            attack=d.get("attack", ""),
            patch=d.get("patch", ""),
            cwe=d.get("cwe", "N/A"),
            owasp=d.get("owasp", "N/A"),
            cve=cve_m.group(0).upper() if cve_m else d.get("cve", ""),
            cvss=cvss,
            kev=kev,
            capec=list(d.get("capec", []) or []),
            root_cause=d.get("root_cause", ""),
            references=list(d.get("references", []) or []),
            profile=profile,
        )


def sort_key(f: Finding):
    """Sort critical->info, then KEV first, then higher CVSS."""
    return (SEVERITY_ORDER.get(f.severity, 9), 0 if f.kev else 1, -(f.cvss or 0))


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        fp = f.fingerprint()
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out
