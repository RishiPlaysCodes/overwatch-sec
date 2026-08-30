#!/usr/bin/env python3
"""
vulnscan.py — Master multi-target vulnerability scanner (one command).

Pass ONE target and the scanner auto-detects its type and runs the right suite:

  Website     :  python3 vulnscan.py https://example.com
  Mobile      :  python3 vulnscan.py ./app.apk           (or app.ipa)
  Cloud IaC   :  python3 vulnscan.py ./terraform/
  Cloud live  :  python3 vulnscan.py aws                 (or azure / gcp)
  Network/host:  python3 vulnscan.py 10.0.0.5            (IP / CIDR / host)
  Source code :  python3 vulnscan.py ./my-project        (SCA + secrets + SAST)
  Container   :  python3 vulnscan.py nginx:1.21          (image ref)

Coverage spans OWASP Top 10 (Web / Mobile / Cloud), CWE / SANS Top 25, plus
network-service vulns, dependency CVEs, secrets, and container image CVEs.
Discovered CVEs are enriched with NVD CVSS and the CISA KEV catalog
(actively-exploited-in-the-wild flag) so the report prioritizes real risk.

For every finding the report explains:
    - what it is (description)
    - how an attacker exploits it (attack scenario)
    - how to fix it (patch / remediation)
plus CWE + OWASP mapping and (for CVEs) CVSS + KEV status.

>>> AUTHORIZED USE ONLY <<<
Run only against systems / apps / accounts you OWN or are explicitly permitted
to test. DoS / DDoS / stress testing is intentionally NOT included — it is
destructive, not a vulnerability check. This tool detects and explains; it does
not weaponize or run exploit code.
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
import scanner_code
import scanner_container
import scanner_mobile
import scanner_network
import scanner_web

SEVERITIES = ("critical", "high", "medium", "low", "info")

# image ref like name:tag or repo/name:tag or registry/ns/name@sha256:...
_IMAGE_RE = re.compile(r"^([a-z0-9.\-]+(?::[0-9]+)?/)?[a-z0-9._\-/]+(:[\w.\-]+|@sha256:[0-9a-f]{64})$", re.I)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")

# markers used to tell a "cloud/IaC" dir apart from a "source code" dir
_IAC_MARKERS = (".tf", ".tf.json", ".template")
_CODE_MANIFESTS = {"requirements.txt", "package.json", "go.mod", "pom.xml",
                   "build.gradle", "Gemfile", "composer.json", "Cargo.toml", "pyproject.toml"}


def detect_profile(target: str) -> str:
    t = target.lower()
    if t in ("aws", "azure", "gcp"):
        return "cloud"
    if t.endswith((".apk", ".ipa", ".xapk")):
        return "mobile"

    if os.path.isdir(target):
        has_iac = has_code = False
        for root, _d, files in os.walk(target):
            if any(f.endswith(_IAC_MARKERS) for f in files):
                has_iac = True
            if any(f in _CODE_MANIFESTS for f in files) or any(f.endswith((".py", ".js", ".ts", ".go", ".java")) for f in files):
                has_code = True
            # only need a shallow look
            if root != target:
                break
        if has_iac:
            return "cloud"
        if has_code:
            return "code"
        return "code"  # default for a plain directory

    if re.match(r"^https?://", target):
        return "web"
    if _IP_RE.match(target):
        return "network"
    # image ref (has a tag/digest and isn't obviously a hostname URL)
    if _IMAGE_RE.match(target) and (":" in target.split("/")[-1] or "@sha256:" in target):
        return "container"
    if "." in target:
        return "web"  # hostname
    return "web"


DISPATCH = {
    "web": scanner_web.scan,
    "mobile": scanner_mobile.scan,
    "cloud": scanner_cloud.scan,
    "network": scanner_network.scan,
    "code": scanner_code.scan,
    "container": scanner_container.scan,
}


def prompt_for_target() -> str:
    """Interactively ask what to scan when no target is given on the CLI."""
    print(f"\n{C.CYN}{C.BOLD}What do you want to scan?{C.RESET}")
    print("  1) Website / URL            (e.g. https://example.com)")
    print("  2) Network host / IP / CIDR (e.g. 192.168.1.10 or 192.168.1.0/24)")
    print("  3) Mobile app               (path to .apk / .ipa)")
    print("  4) Source code folder       (path to a project dir)")
    print("  5) Container image          (e.g. nginx:1.21)")
    print("  6) Cloud IaC folder         (path to terraform/ etc.)")
    print("  7) Live cloud account       (aws / azure / gcp)")
    print(f"{C.BLU}Tip:{C.RESET} you can also just type the target directly.\n")
    choice = input("Choice [1-7] or target: ").strip()
    hints = {
        "1": "Enter the URL: ",
        "2": "Enter host/IP/CIDR: ",
        "3": "Enter path to .apk/.ipa: ",
        "4": "Enter path to the code folder: ",
        "5": "Enter image ref (name:tag): ",
        "6": "Enter path to the IaC folder: ",
        "7": "Enter provider (aws/azure/gcp): ",
    }
    if choice in hints:
        return input(hints[choice]).strip()
    return choice  # user typed the target directly


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
    kev = [f for f in findings if "CISA KEV" in f.get("evidence", "")]

    with open(md_path, "w") as fh:
        fh.write("# Vulnerability Assessment Report\n\n")
        fh.write(f"- **Profile:** {report['profile']}\n")
        fh.write(f"- **Target:** {report['target']}\n")
        fh.write(f"- **Time (UTC):** {report['started']}\n")
        fh.write(f"- **Total findings:** {len(findings)}\n\n")

        counts: dict[str, int] = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        fh.write("| Severity | Count |\n|---|---|\n")
        for sev in SEVERITIES:
            if sev in counts:
                fh.write(f"| {sev.upper()} | {counts[sev]} |\n")
        fh.write("\n")

        if kev:
            fh.write("> ⚠️ **Actively exploited (CISA KEV):** "
                     f"{len(kev)} finding(s) match CVEs known to be exploited in the wild — patch these first.\n\n")

        fh.write("---\n\n## Findings\n\n")
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
    colors = {"critical": C.MAG, "high": C.RED, "medium": C.YEL, "low": C.BLU, "info": C.CYN}
    for sev in SEVERITIES:
        if sev in counts:
            print(f"  {colors.get(sev,'')}{sev.upper():8}{C.RESET}: {counts[sev]}")

    kev = [f for f in report["findings"] if "CISA KEV" in f.get("evidence", "")]
    if kev:
        print(f"\n{C.MAG}{C.BOLD}⚠️  Actively exploited (CISA KEV) — patch first:{C.RESET}")
        for f in kev[:8]:
            print(f"  • {f['evidence'][:80]}")

    top = [f for f in report["findings"] if f["severity"] in ("critical", "high")]
    if top:
        print(f"\n{C.RED}{C.BOLD}Top critical/high issues:{C.RESET}")
        for f in top[:8]:
            print(f"  • [{f['severity'].upper()}] {f['title']} ({f['cwe']}) — {f['evidence'][:60]}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Master multi-target vulnerability scanner "
                    "(web / mobile / cloud / network / code / container). Authorized use only.")
    ap.add_argument("target", nargs="?", default=None,
                    help="URL | host/IP/CIDR | app.apk/.ipa | dir (IaC or source) | image:tag | aws/azure/gcp "
                         "(omit to be asked interactively)")
    ap.add_argument("--type", choices=["auto", "web", "mobile", "cloud", "network", "code", "container"],
                    default="auto", help="force target type (default: auto-detect)")
    ap.add_argument("--out", default=None, help="output directory")
    ap.add_argument("--skip", default="", help="comma list of tools to skip")
    ap.add_argument("--yes", action="store_true", help="skip authorization prompt (owned assets / CI)")
    args = ap.parse_args()

    target = args.target or prompt_for_target()
    if not target:
        err("No target given. Nothing to scan.")
        return 2
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

    scan_fn = DISPATCH.get(profile, scanner_web.scan)
    report = scan_fn(target, outdir, skip)

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
