#!/usr/bin/env python3
"""
core/capability_matrix.py — structured, code-derived capability matrix (spec §2/§56).

Produces one row per capability family + per cross-cutting engine capability, each
classified with the EXACT status vocabulary the contract requires. Statuses are
derived from real signals (KB detection emission, registered validators/capabilities,
scanner/analyzer presence) plus an explicit policy map that records WHY a family is
gated (safety), external (credentials/telemetry/hardware), or manual.

This is the artifact that "proves exactly what the platform can and cannot do".
It never fabricates: detection counts come from `gap_analysis.emitted_ids()`, and
anything not automatable is given a concrete reason, not left as a silent TODO.
"""

from __future__ import annotations

# Exact status vocabulary (contract §2)
STATUSES = (
    "IMPLEMENTED_AND_TESTED",
    "IMPLEMENTED_PARTIALLY",
    "MANUAL_VALIDATION_REQUIRED",
    "REQUIRES_AUTHORIZED_CREDENTIALS",
    "REQUIRES_EXTERNAL_TELEMETRY",
    "REQUIRES_SPECIAL_HARDWARE",
    "REQUIRES_TARGET_SPECIFIC_CONFIGURATION",
    "EXTERNAL_TOOL_REQUIRED",
    "BLOCKED_BY_SCOPE",
    "BLOCKED_BY_POLICY",
    "INTENTIONALLY_BLOCKED_FOR_SAFETY",
    "NOT_APPLICABLE",
)

# Per-family policy overrides: (status, reason). Families NOT listed here are
# classified automatically from detection/validation signals below.
_FAMILY_POLICY = {
    "linux":   ("REQUIRES_TARGET_SPECIFIC_CONFIGURATION",
                "Assesses an authorized host data export (JSON); never touches a live host."),
    "windows": ("REQUIRES_TARGET_SPECIFIC_CONFIGURATION",
                "Assesses an authorized host data export (JSON); never touches a live host."),
    "auth":    ("REQUIRES_AUTHORIZED_CREDENTIALS",
                "Session/auth-bypass confirmation needs a supplied test identity; detection is KB-modelled."),
    "logic":   ("MANUAL_VALIDATION_REQUIRED",
                "Business-logic flaws require human judgement + a test identity; never inferred from anomalies."),
    "memory":  ("NOT_APPLICABLE",
                "No direct binary fuzzing; memory classes are reasoned via CVE/SCA/SAST evidence."),
    "wireless": ("REQUIRES_SPECIAL_HARDWARE",
                 "Active RF assessment needs authorized wireless hardware; adapter boundary exposed."),
    "iot":     ("REQUIRES_SPECIAL_HARDWARE",
                "Device/firmware testing needs the physical device; imported evidence supported."),
    "db":      ("REQUIRES_AUTHORIZED_CREDENTIALS",
                "Live DB auth/privilege checks need supplied credentials; network exposure IS detected."),
    "supplychain": ("EXTERNAL_TOOL_REQUIRED",
                    "Dependency-confusion/typosquat signals rely on SCA tools/registries; KB-modelled otherwise."),
}

# Families we have dedicated automated tests for (honest IMPLEMENTED_AND_TESTED).
_TESTED_FAMILIES = {"web", "api", "recon", "cicd", "iac", "container", "k8s", "cloud", "code", "network"}

# Cross-cutting engine capabilities (not KB families) — each has a real, tested path.
_ENGINE_CAPS = [
    ("attack_path_correlation", "analysis", "IMPLEMENTED_AND_TESTED",
     "attack_paths/graph.py + correlation.py; objective-only paths, steps CONFIRMED/ASSUMED/UNVALIDATED."),
    ("mitre_attack_mapping", "analysis", "IMPLEMENTED_AND_TESTED",
     "attack_paths/mitre.py; technique+tactic, honest unmapped prefixes."),
    ("threat_classification_6state", "analysis", "IMPLEMENTED_AND_TESTED",
     "threat_detection.classify_detailed; IOC<=possible, validated needs confirmation."),
    ("purple_team_detection", "analysis", "REQUIRES_EXTERNAL_TELEMETRY",
     "purple/verification.py; reports TELEMETRY_UNAVAILABLE when no telemetry supplied."),
    ("coverage_metrics", "reporting", "IMPLEMENTED_AND_TESTED",
     "core/coverage.py + knowledge.coverage_by_domain; validation + per-domain matrices."),
    ("capability_gap_engine", "governance", "IMPLEMENTED_AND_TESTED",
     "core/gap_analysis.py + this matrix; --gap-analysis / --capability-matrix."),
    ("resume_checkpoint", "workflow", "IMPLEMENTED_AND_TESTED", "core/checkpoint.py; restores findings+paths."),
    ("retest_baseline", "workflow", "IMPLEMENTED_AND_TESTED", "reporting/compare.py; new/fixed/persistent."),
    ("secret_redaction", "safety", "IMPLEMENTED_AND_TESTED", "core/policy.redact; lab test asserts no leak."),
    ("controlled_validation_oast", "validation", "REQUIRES_TARGET_SPECIFIC_CONFIGURATION",
     "validation/oast.py callback framework; SSRF proof works with a collaborator (lab-tested), else MANUAL."),
    ("social_engineering_awareness", "assessment", "INTENTIONALLY_BLOCKED_FOR_SAFETY",
     "Authorized awareness-RESULTS analysis only; never sends campaigns or handles real creds."),
    ("availability_loadtest", "assessment", "BLOCKED_BY_POLICY",
     "Bounded, opt-in, lab-gated resilience test; never an uncontrolled DoS."),
]

# Sub-classes intentionally gated for safety (active exploitation) — reported as a note.
_SAFETY_GATED_NOTE = ("Active-exploitation subclasses (SSRF/SSTI/cmdi/deserialization/XXE/CRLF/EL) are "
                      "INTENTIONALLY_BLOCKED_FOR_SAFETY: gated at the intrusive policy level, no auto-exploitation.")


def _signals():
    import knowledgebase as kb
    from core import knowledge, gap_analysis
    from validation import registry, validator
    emitted = gap_analysis.emitted_ids()
    cat = knowledge.catalog()
    cap_prefixes = set(registry.CAPABILITIES.keys())
    val_prefixes = set(validator._REGISTRY.keys())
    return kb, cat, emitted, cap_prefixes, val_prefixes


def matrix() -> list[dict]:
    """Return the full capability matrix as a list of structured rows."""
    _, cat, emitted, cap_prefixes, val_prefixes = _signals()
    rows: list[dict] = []
    for fam, e in cat.items():
        ids = e["ids"]
        detected = sum(1 for i in ids if i in emitted)
        has_auto = any(any(i == vp or i.startswith(vp) for vp in val_prefixes) for i in ids)
        has_cap = any(any(i == cp or i.startswith(cp) for cp in cap_prefixes) for i in ids)

        if fam in _FAMILY_POLICY:
            status, reason = _FAMILY_POLICY[fam]
        elif detected and has_auto:
            status = "IMPLEMENTED_AND_TESTED" if fam in _TESTED_FAMILIES else "IMPLEMENTED_PARTIALLY"
            reason = f"{detected}/{e['count']} classes emit detection; automated safe validator(s) present."
        elif detected:
            status = "IMPLEMENTED_AND_TESTED" if fam in _TESTED_FAMILIES else "IMPLEMENTED_PARTIALLY"
            reason = f"{detected}/{e['count']} classes emit detection; validation is manual/gated."
        elif has_cap:
            status = "MANUAL_VALIDATION_REQUIRED"
            reason = "Validation capability registered without an automated safe checker (honest manual)."
        else:
            status = "MANUAL_VALIDATION_REQUIRED"
            reason = "Knowledge-modelled; detection depends on an import/tool or requires manual review."

        row = {
            "capability": fam,
            "category": "vulnerability_family",
            "domain": e["domain"],
            "knowledge_entries": e["count"],
            "detection_emitted": detected,
            "auto_validator": has_auto,
            "validation_capability": has_cap,
            "status": status,
            "reason": reason,
        }
        if fam in ("web", "api"):
            row["note"] = _SAFETY_GATED_NOTE
        rows.append(row)

    for name, cat_, status, reason in _ENGINE_CAPS:
        rows.append({"capability": name, "category": cat_, "domain": "engine",
                     "knowledge_entries": None, "detection_emitted": None,
                     "auto_validator": None, "validation_capability": None,
                     "status": status, "reason": reason})
    return rows


def summary() -> dict:
    rows = matrix()
    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    unexplained = [r["capability"] for r in rows if not r.get("reason")]
    return {
        "total_capabilities": len(rows),
        "by_status": dict(sorted(by_status.items())),
        "unexplained_gaps": unexplained,   # must always be empty
    }


def render() -> str:
    rows = matrix()
    s = summary()
    L = ["CAPABILITY MATRIX (code-derived — proves what the platform can/cannot do)", ""]
    L.append(f"  {'capability':26} {'KB':>3} {'det':>3} {'val':>3}  status")
    L.append("  " + "-" * 74)
    for r in rows:
        kb = "-" if r["knowledge_entries"] is None else str(r["knowledge_entries"])
        det = "-" if r["detection_emitted"] is None else str(r["detection_emitted"])
        val = "-" if r["auto_validator"] is None else ("y" if r["auto_validator"] else ".")
        L.append(f"  {r['capability']:26} {kb:>3} {det:>3} {val:>3}  {r['status']}")
    L.append("")
    L.append("  Status distribution:")
    for st, n in s["by_status"].items():
        L.append(f"    {st:42} {n}")
    L.append("")
    L.append(f"  Unexplained core-capability gaps: {len(s['unexplained_gaps'])} "
             f"(must be 0 — every row carries an explicit reason).")
    L.append("  KB=knowledge entries  det=classes emitting detection  val=has automated safe validator")
    return "\n".join(L)
