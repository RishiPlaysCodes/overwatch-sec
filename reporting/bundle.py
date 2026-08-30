#!/usr/bin/env python3
"""
reporting/bundle.py — professional report bundle (spec §32).

Produces a structured deliverable directory:

    reports/
      executive-report.md   (+ .pdf)   — business-level summary
      technical-report.md   (+ .pdf)   — full technical findings (existing writer)
      findings.json
      attack-paths.json
      coverage.json
      detection.json                    — purple-team detection (if any)
      social.json                       — awareness metrics (if any)
      evidence/<fingerprint>.json       — per-finding structured evidence (redacted)

Reuses the existing reporting.report writers for the technical/HTML output.
"""

from __future__ import annotations

import json
import os

from . import report as _report


def _executive_md(assessment) -> str:
    s = _report.summarize(assessment)
    L = ["# Executive Security Report", ""]
    L.append(f"**Target:** {assessment.target}  \n"
             f"**Profile:** {assessment.profile}  |  **Mode:** {assessment.mode}  |  "
             f"**Type:** {assessment.kind}")
    L.append("")
    L.append("## Overall posture\n")
    L.append(f"- **Security score:** {s['security_score']}/100")
    L.append(f"- **Findings:** {s['total']} active "
             f"(critical {s['counts']['critical']}, high {s['counts']['high']}, "
             f"medium {s['counts']['medium']}, low {s['counts']['low']})"
             + (f", {s['muted']} triaged-out" if s.get("muted") else ""))
    L.append(f"- **Actively-exploited (CISA KEV):** {s['kev_count']}")
    L.append(f"- **Attack paths:** {s['attack_paths']} (top risk {s['top_attack_risk']}/100)")
    if assessment.detection:
        ds = assessment.detection.get("summary", {})
        L.append(f"- **Detection coverage:** {ds.get('detection_rate', 0)}% "
                 f"({ds.get('gaps', 0)} gap(s))")
    if assessment.social:
        L.append(f"- **Human-risk score:** {assessment.social.get('human_risk_score')}/100 "
                 f"(click {assessment.social.get('click_rate')}%)")
    L.append("")
    # top risks (business framing)
    top = [f for f in assessment.findings if f.severity in ("critical", "high")][:6]
    if top:
        L.append("## Top risks to address first\n")
        for f in top:
            vs = "validated" if f.validation in ("validated", "exploitable") else f.validation
            L.append(f"- **{f.title}** ({f.severity.upper()}, {vs}) — {f.asset}")
        L.append("")
    L.append("## What was assessed\n")
    if assessment.coverage:
        cs = assessment.coverage.summary()
        L.append(f"- Stages run: {cs.get('stages_ran')} | skipped: {cs.get('stages_skipped')} | "
                 f"tools executed: {len(cs.get('tools_executed', []))}")
    L.append("\n> This is a measurable, point-in-time assessment — not a guarantee of "
             "'100% secure'. Findings are evidence-backed where validated and flagged for "
             "manual review otherwise.")
    return "\n".join(L) + "\n"


def write_bundle(assessment, outdir: str, pdf: bool = True) -> dict:
    reports = os.path.join(outdir, "reports")
    evidence = os.path.join(reports, "evidence")
    os.makedirs(evidence, exist_ok=True)
    paths = {}

    # executive report
    exec_md = os.path.join(reports, "executive-report.md")
    with open(exec_md, "w") as fh:
        fh.write(_executive_md(assessment))
    paths["executive_md"] = exec_md

    # technical report (reuse existing markdown + html writers)
    tech_md = _report.write_markdown(assessment, os.path.join(reports, "technical-report.md"))
    paths["technical_md"] = tech_md
    try:
        paths["technical_html"] = _report.write_html(assessment, os.path.join(reports, "technical-report.html"))
        from . import graph_html
        if assessment.findings:
            paths["graph_html"] = graph_html.write_graph_html(assessment, os.path.join(reports, "attack-graph.html"))
    except Exception:
        pass

    # json artifacts
    data = assessment.to_dict()
    with open(os.path.join(reports, "findings.json"), "w") as fh:
        json.dump(data.get("findings", []), fh, indent=2)
    paths["findings_json"] = os.path.join(reports, "findings.json")
    with open(os.path.join(reports, "attack-paths.json"), "w") as fh:
        json.dump(data.get("attack_paths", []), fh, indent=2)
    paths["attack_paths_json"] = os.path.join(reports, "attack-paths.json")
    with open(os.path.join(reports, "coverage.json"), "w") as fh:
        json.dump(data.get("coverage", {}), fh, indent=2)
    paths["coverage_json"] = os.path.join(reports, "coverage.json")
    if assessment.detection:
        with open(os.path.join(reports, "detection.json"), "w") as fh:
            json.dump(assessment.detection, fh, indent=2)
        paths["detection_json"] = os.path.join(reports, "detection.json")
    if assessment.social:
        with open(os.path.join(reports, "social.json"), "w") as fh:
            json.dump(assessment.social, fh, indent=2)
        paths["social_json"] = os.path.join(reports, "social.json")

    # SARIF for CI
    try:
        from . import sarif
        paths["sarif"] = sarif.write_sarif(assessment, os.path.join(reports, "report.sarif"))
    except Exception:
        pass

    # per-finding structured evidence (already redacted upstream)
    n = 0
    for f in assessment.findings:
        fp = f.fingerprint()
        rec = {"finding_id": f.id, "fingerprint": fp, "title": f.title, "severity": f.severity,
               "asset": f.asset, "status": f.status, "confidence": f.confidence,
               "validation": f.validation, "validation_evidence": f.validation_evidence,
               "detection_evidence": f.evidence, "cve": f.cve, "cwe": f.cwe,
               "owasp": f.owasp, "capec": f.capec, "mitre": f.mitre, "cleanup": "none"}
        with open(os.path.join(evidence, f"{fp}.json"), "w") as fh:
            json.dump(rec, fh, indent=2)
        n += 1
    paths["evidence_dir"] = evidence

    # PDFs (best-effort / dependency-free fallback)
    if pdf:
        try:
            from . import pdf as _pdf
            paths["executive_pdf"] = _pdf.write_pdf(
                assessment, os.path.join(reports, "executive-report.pdf"),
                paths.get("technical_html"))
            paths["technical_pdf"] = _pdf.write_pdf(
                assessment, os.path.join(reports, "technical-report.pdf"),
                paths.get("technical_html"))
        except Exception:
            pass

    # manifest
    manifest = {"bundle": "overwatch", "target": assessment.target, "profile": assessment.profile,
                "mode": assessment.mode, "scan_id": assessment.scan_id,
                "artifacts": sorted(os.path.basename(p) for p in paths.values() if os.path.isfile(p)),
                "evidence_files": n}
    with open(os.path.join(reports, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    paths["manifest"] = os.path.join(reports, "manifest.json")
    return paths
