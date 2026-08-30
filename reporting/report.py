#!/usr/bin/env python3
"""
reporting/report.py — render an Assessment into md / json / csv / html.

The report leads with an executive summary (security score, severity counts,
KEV, attack paths), then full technical findings (with confidence, validation
state, CWE/OWASP/CVSS/KEV/ATT&CK, attack scenario, remediation), then attack
paths and measurable coverage. It never claims "100% secure".
"""

from __future__ import annotations

import csv
import html
import json
import os

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}


def security_score(findings) -> int:
    """0 (worst) .. 100 (clean). Deduct per finding, KEV hits harder."""
    penalty = 0
    for f in findings:
        penalty += _SEV_WEIGHT.get(f.severity, 0) * (1.6 if f.kev else 1.0)
    return max(0, round(100 - min(penalty, 100)))


def _counts(findings) -> dict:
    c = {k: 0 for k in _SEV_ORDER}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def summarize(assessment) -> dict:
    fs = assessment.findings
    counts = _counts(fs)
    kev = [f for f in fs if f.kev]
    return {
        "target": assessment.target,
        "kind": assessment.kind,
        "profile": assessment.profile,
        "mode": assessment.mode,
        "security_score": security_score(fs),
        "counts": counts,
        "total": len(fs),
        "kev_count": len(kev),
        "attack_paths": len(assessment.attack_paths),
        "top_attack_risk": (assessment.attack_paths[0]["risk_score"] if assessment.attack_paths else 0),
        "out_of_scope_dropped": len(assessment.out_of_scope_dropped),
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def write_json(assessment, path: str) -> str:
    data = assessment.to_dict()
    data["summary"] = summarize(assessment)
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# CSV (findings table)
# ---------------------------------------------------------------------------
def write_csv(assessment, path: str) -> str:
    cols = ["severity", "confidence", "validation", "status", "id", "title",
            "asset", "cwe", "owasp", "cve", "cvss", "kev", "mitre"]
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for f in assessment.findings:
            w.writerow([f.severity, f.confidence, f.validation, f.status, f.id, f.title,
                        f.asset, f.cwe, f.owasp, f.cve, f.cvss if f.cvss is not None else "",
                        "yes" if f.kev else "no", "|".join(f.mitre)])
    return path


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def write_markdown(assessment, path: str) -> str:
    s = summarize(assessment)
    fs = assessment.findings
    L = []
    L.append("# Security Assessment Report\n")
    L.append(f"- **Target:** {assessment.target}")
    L.append(f"- **Type:** {assessment.kind}  |  **Profile:** {assessment.profile}  |  **Mode:** {assessment.mode}")
    L.append(f"- **Policy:** {assessment.policy.summary()}")
    L.append(f"- **Scope:** {assessment.scope.describe()}")
    L.append("")
    L.append("## Executive summary\n")
    L.append(f"- **Security score:** {s['security_score']}/100")
    L.append(f"- **Findings:** {s['total']}  "
             f"(critical {s['counts']['critical']}, high {s['counts']['high']}, "
             f"medium {s['counts']['medium']}, low {s['counts']['low']}, info {s['counts']['info']})")
    L.append(f"- **Actively exploited (CISA KEV):** {s['kev_count']}")
    L.append(f"- **Attack paths:** {s['attack_paths']} (top risk {s['top_attack_risk']}/100)")
    if s["out_of_scope_dropped"]:
        L.append(f"- **Out-of-scope assets dropped:** {s['out_of_scope_dropped']}")
    L.append("")
    if any(f.kev for f in fs):
        L.append("> ⚠️ **Patch first:** findings tied to actively-exploited CVEs (CISA KEV) below.\n")

    L.append("## Attack paths\n")
    if not assessment.attack_paths:
        L.append("_No multi-step attack paths correlated._\n")
    for i, p in enumerate([p for p in assessment.attack_paths if p["length"] > 1][:10], 1):
        L.append(f"**Path {i}** — asset `{p['asset']}` — risk **{p['risk_score']}/100**"
                 + (" — entry point" if p["entry"] else ""))
        L.append("")
        L.append("```")
        L.append(p["chain"])
        L.append("```")
        L.append("")

    L.append("## Findings\n")
    if not fs:
        L.append("_No findings from the checks that ran._\n")
    for i, f in enumerate(sorted(fs, key=lambda x: _SEV_ORDER.get(x.severity, 9)), 1):
        L.append(f"### {i}. [{f.severity.upper()}] {f.title}")
        L.append("")
        L.append(f"- **Confidence:** {f.confidence}  |  **Validation:** {f.validation}  |  **Status:** {f.status}")
        L.append(f"- **Asset:** `{f.asset}`" + (f"  |  **Component:** `{f.component}`" if f.component else ""))
        meta = f"- **CWE:** {f.cwe}  |  **OWASP:** {f.owasp}"
        if f.cve:
            meta += f"  |  **CVE:** {f.cve}"
        if f.cvss is not None:
            meta += f"  |  **CVSS:** {f.cvss}"
        if f.kev:
            meta += "  |  **CISA KEV:** yes"
        if f.mitre:
            meta += f"  |  **ATT&CK:** {', '.join(f.mitre)}"
        L.append(meta)
        L.append(f"- **Evidence:** `{f.evidence}`")
        L.append("")
        if f.description:
            L.append(f"**What it is:** {f.description}\n")
        if f.attack:
            L.append(f"**Attack scenario:** {f.attack}\n")
        if f.patch:
            L.append(f"**Fix / remediation:** {f.patch}\n")
        L.append("---\n")

    # coverage
    if assessment.coverage:
        L.append("## Coverage\n")
        L.append("```")
        L.append(assessment.coverage.render())
        L.append("```")
    L.append("\n> Detection & authorized-assessment tool. Findings are indicators — "
             "validate before acting. This is not a claim of '100% secure'.")
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")
    return path


# ---------------------------------------------------------------------------
# HTML (self-contained dashboard)
# ---------------------------------------------------------------------------
_SEV_COLOR = {"critical": "#8e44ad", "high": "#e74c3c", "medium": "#e67e22",
              "low": "#3498db", "info": "#7f8c8d"}


def write_html(assessment, path: str) -> str:
    s = summarize(assessment)
    fs = sorted(assessment.findings, key=lambda x: _SEV_ORDER.get(x.severity, 9))

    def esc(x):
        return html.escape(str(x))

    cards = "".join(
        f'<div class="card" style="border-top:4px solid {_SEV_COLOR[k]}">'
        f'<div class="num">{s["counts"][k]}</div><div class="lbl">{k.upper()}</div></div>'
        for k in ("critical", "high", "medium", "low", "info")
    )
    score = s["security_score"]
    score_color = "#27ae60" if score >= 80 else "#e67e22" if score >= 50 else "#e74c3c"

    paths_html = ""
    for i, p in enumerate([p for p in assessment.attack_paths if p["length"] > 1][:10], 1):
        steps = " &rarr; ".join(esc(st["finding"]) for st in p["steps"])
        paths_html += (f'<div class="path"><b>Path {i}</b> — <code>{esc(p["asset"])}</code> '
                       f'— risk <b>{p["risk_score"]}/100</b><div class="chain">Internet &rarr; {steps}</div></div>')
    if not paths_html:
        paths_html = "<p><i>No multi-step attack paths correlated.</i></p>"

    rows = ""
    for f in fs:
        kev = '<span class="kev">KEV</span>' if f.kev else ""
        rows += (
            f'<tr><td><span class="sev" style="background:{_SEV_COLOR[f.severity]}">{f.severity.upper()}</span></td>'
            f'<td>{esc(f.title)} {kev}</td><td>{esc(f.confidence)}</td><td>{esc(f.validation)}</td>'
            f'<td><code>{esc(f.asset)}</code></td><td>{esc(f.cwe)}</td><td>{esc(f.owasp)}</td>'
            f'<td>{esc(", ".join(f.mitre))}</td>'
            f'<td class="rem">{esc(f.patch)}</td></tr>'
        )

    cov = esc(assessment.coverage.render()) if assessment.coverage else ""
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vulnscan report — {esc(assessment.target)}</title>
<style>
*{{box-sizing:border-box}}body{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}}
header{{background:#111a24;padding:24px 32px;border-bottom:2px solid #1f2d3a}}
h1{{margin:0;font-size:20px}}.sub{{color:#8aa;margin-top:6px;font-size:13px}}
.wrap{{padding:24px 32px;max-width:1200px;margin:auto}}
.score{{font-size:44px;font-weight:700;color:{score_color}}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.card{{background:#16212c;border-radius:8px;padding:14px 20px;min-width:96px;text-align:center}}
.num{{font-size:26px;font-weight:700}}.lbl{{font-size:11px;color:#9ab;letter-spacing:1px}}
h2{{border-bottom:1px solid #26333f;padding-bottom:6px;margin-top:32px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #22303c;vertical-align:top}}
th{{color:#9ab;font-size:11px;text-transform:uppercase}}
.sev{{color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}}
.kev{{background:#8e44ad;color:#fff;padding:1px 6px;border-radius:4px;font-size:10px;margin-left:6px}}
code{{color:#7fd1ff}}.rem{{color:#bcd;max-width:320px}}
.path{{background:#16212c;border-radius:8px;padding:12px 16px;margin:10px 0}}
.chain{{margin-top:6px;color:#ffd27f;font-size:13px}}
pre{{background:#16212c;padding:16px;border-radius:8px;overflow:auto;white-space:pre-wrap}}
.foot{{color:#789;font-size:12px;margin-top:24px}}
</style></head><body>
<header><h1>🛡️ VULNSCAN — Security Assessment Report</h1>
<div class="sub">Target: <b>{esc(assessment.target)}</b> &nbsp;|&nbsp; Type: {esc(assessment.kind)}
&nbsp;|&nbsp; Profile: {esc(assessment.profile)} &nbsp;|&nbsp; Mode: {esc(assessment.mode)}
&nbsp;|&nbsp; Scope: {esc(assessment.scope.describe())}</div></header>
<div class="wrap">
<h2>Executive summary</h2>
<div>Security score: <span class="score">{score}</span> / 100 &nbsp;&nbsp;
Actively-exploited (KEV): <b>{s['kev_count']}</b> &nbsp;|&nbsp; Attack paths: <b>{s['attack_paths']}</b>
(top risk {s['top_attack_risk']}/100)</div>
<div class="cards">{cards}</div>
<h2>Attack paths</h2>{paths_html}
<h2>Findings ({s['total']})</h2>
<table><thead><tr><th>Severity</th><th>Title</th><th>Confidence</th><th>Validation</th>
<th>Asset</th><th>CWE</th><th>OWASP</th><th>ATT&amp;CK</th><th>Remediation</th></tr></thead>
<tbody>{rows or '<tr><td colspan=9><i>No findings.</i></td></tr>'}</tbody></table>
<h2>Coverage</h2><pre>{cov}</pre>
<div class="foot">Authorized security assessment tool — detection &amp; validation only.
Findings are indicators; validate before acting. Not a claim of "100% secure".</div>
</div></body></html>"""
    with open(path, "w") as fh:
        fh.write(doc)
    return path


# ---------------------------------------------------------------------------
def write_all(assessment, outdir: str, formats=("md", "json", "csv", "html")) -> dict:
    os.makedirs(outdir, exist_ok=True)
    paths = {}
    if "json" in formats:
        paths["json"] = write_json(assessment, os.path.join(outdir, "report.json"))
    if "csv" in formats:
        paths["csv"] = write_csv(assessment, os.path.join(outdir, "report.csv"))
    if "md" in formats:
        paths["md"] = write_markdown(assessment, os.path.join(outdir, "report.md"))
    if "html" in formats:
        paths["html"] = write_html(assessment, os.path.join(outdir, "report.html"))
    return paths
