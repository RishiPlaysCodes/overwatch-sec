#!/usr/bin/env python3
"""
vulnscan.py — Master multi-target vulnerability scanner (one command).

Pass ONE target and the scanner auto-detects its type and runs the right suite:

  Website   :  python3 vulnscan.py https://example.com
  Mobile    :  python3 vulnscan.py ./app.apk        (or app.ipa)
  Cloud IaC :  python3 vulnscan.py ./terraform/
  Cloud live:  python3 vulnscan.py aws              (or azure / gcp)

Coverage: OWASP Top 10 (Web / Mobile / Cloud) and CWE / SANS Top 25 categories.
For every finding the report explains:
    - what it is (description)
    - how an attacker exploits it (attack scenario)
    - how to fix it (patch / remediation)
plus CWE + OWASP mapping.

>>> AUTHORIZED USE ONLY <<<
Run only against systems / apps / cloud accounts you OWN or are explicitly
permitted to test. DoS / DDoS / stress testing is intentionally NOT included —
it is destructive, not a vulnerability check.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

from common import C, banner, err, ok, warn
from knowledgebase import SEVERITY_ORDER

import scanner_cloud
import scanner_mobile
import scanner_web


def detect_profile(target: str) -> str:
    t = target.lower()
    if t in ("aws", "azure", "gcp"):
        return "cloud"
    if t.endswith((".apk", ".ipa", ".xapk")):
        return "mobile"
    if os.path.isdir(target):
        # IaC directory heuristic
        for root, _d, files in os.walk(target):
            if any(f.endswith((".tf", ".tf.json")) or f in ("main.tf",) or f.endswith(".template") for f in files):
                return "cloud"
            if any(f.endswith((".yaml", ".yml", ".json")) for f in files):
                return "cloud"
            break
        return "cloud"
    if re.match(r"^https?://", target) or "." in target:
        return "web"
    return "web"


def authorize(target: str, profile: str, auto_yes: bool) -> bool:
    if auto_yes:
        return True
    print(
        f"{C.YEL}{C.BOLD}\nAUTHORIZATION CHECK{C.RESET}\n"
        f"About to run a {C.BOLD}{profile}{C.RESET} scan on: {C.BOLD}{target}{C.RESET}\n"
        "Continue only if you OWN this target or have EXPLICIT WRITTEN PERMISSION to test it.\n"
    )
    return input("Type 'I AM AUTHORIZED' to continue: ").strip() == "I AM AUTHORIZED"


def write_reports(report: dict, outdir: str) -> tuple[str, str]:
    json_path = os.path.join(outdir, "report.json")
    with open(json_path, "w") as fh:
        json.dump(report, fh, indent=2)

    md_path = os.path.join(outdir, "report.md")
    findings = sorted(report["findings"], key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))
    with open(md_path, "w") as fh:
        fh.write(f"# Vulnerability Assessment Report\n\n")
        fh.write(f"- **Profile:** {report['profile']}\n")
        fh.write(f"- **Target:** {report['target']}\n")
        fh.write(f"- **Time (UTC):** {report['started']}\n")
        fh.write(f"- **Total findings:** {len(findings)}\n\n")

        # Severity summary table
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        fh.write("| Severity | Count |\n|---|---|\n")
        for sev in ("high", "medium", "low", "info"):
            if sev in counts:
                fh.write(f"| {sev.upper()} | {counts[sev]} |\n")
        fh.write("\n---\n\n## Findings\n\n")

        if not findings:
            fh.write("_No findings from the checks that ran._\n\n")
        for i, f in enumerate(findings, 1):
            fh.write(f"### {i}. [{f['severity'].upper()}] {f['title']}\n\n")
            fh.write(f"- **CWE:** {f['cwe']} &nbsp;|&nbsp; **OWASP:** {f['owasp']}\n")
            fh.write(f"- **Evidence:** `{f['evidence']}`\n\n")
            fh.write(f"**What it is:** {f['description']}\n\n")
            fh.write(f"**Attack scenario:** {f['attack']}\n\n")
            fh.write(f"**Fix / patch:** {f['patch']}\n\n")
            fh.write("---\n\n")

        fh.write("## Tools\n\n")
        for t in report["tools"]:
            line = f"- **{t['tool']}**: {t['status']}"
            if t.get("output"):
                line += f" — `{t['output']}`"
            if t.get("reason"):
                line += f" ({t['reason']})"
            fh.write(line + "\n")
        fh.write("\n> Findings are indicators. Validate manually before acting. "
                 "DoS/DDoS testing intentionally excluded.\n")
    return json_path, md_path


def print_summary(report: dict) -> None:
    banner("SUMMARY")
    counts: dict[str, int] = {}
    for f in report["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    colors = {"high": C.RED, "medium": C.YEL, "low": C.BLU, "info": C.CYN}
    for sev in ("high", "medium", "low", "info"):
        if sev in counts:
            print(f"  {colors.get(sev,'')}{sev.upper():6}{C.RESET}: {counts[sev]}")
    # Top high-severity titles
    highs = [f for f in report["findings"] if f["severity"] == "high"]
    if highs:
        print(f"\n{C.RED}{C.BOLD}Top high-severity issues:{C.RESET}")
        for f in highs[:8]:
            print(f"  • {f['title']} ({f['cwe']}) — {f['evidence'][:70]}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Master multi-target vulnerability scanner (web / mobile / cloud). Authorized use only.")
    ap.add_argument("target", help="URL | host | app.apk/.ipa | IaC dir | aws/azure/gcp")
    ap.add_argument("--type", choices=["auto", "web", "mobile", "cloud"], default="auto",
                    help="force target type (default: auto-detect)")
    ap.add_argument("--out", default=None, help="output directory")
    ap.add_argument("--skip", default="", help="comma list of tools to skip")
    ap.add_argument("--yes", action="store_true", help="skip authorization prompt (owned assets / CI)")
    args = ap.parse_args()

    target = args.target
    profile = args.type if args.type != "auto" else detect_profile(target)
    if profile == "web" and not re.match(r"^https?://", target) and target not in ("aws", "azure", "gcp"):
        target = "https://" + target
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}

    banner(f"vulnscan — profile detected: {profile.upper()}")
    ok(f"target: {target}")

    if not authorize(target, profile, args.yes):
        err("Authorization not confirmed. Aborting.")
        return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", target)[:40]
    outdir = args.out or f"report-{profile}-{safe}-{ts}"
    os.makedirs(outdir, exist_ok=True)

    if profile == "web":
        report = scanner_web.scan(target, outdir, skip)
    elif profile == "mobile":
        report = scanner_mobile.scan(target, outdir, skip)
    else:
        report = scanner_cloud.scan(target, outdir, skip)

    report["started"] = ts
    json_path, md_path = write_reports(report, outdir)
    print_summary(report)
    ok(f"JSON report : {json_path}")
    ok(f"Markdown    : {md_path}")
    ok(f"Output dir  : {outdir}/")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        err("interrupted")
        sys.exit(130)
