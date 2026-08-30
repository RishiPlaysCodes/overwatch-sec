#!/usr/bin/env python3
"""
vulnscan.py — Universal Security Assessment & Authorized Adversary-Emulation platform.

One command, target auto-detection, profile + mode driven, scope- and
policy-enforced, with measurable coverage and industry-grade reports.

    vulnscan example.com
    vulnscan example.com --profile bugbounty --mode deep --scope scope.txt
    vulnscan 10.0.0.0/24 --profile redteam --mode fast --yes
    vulnscan ./app.apk   --profile mobile
    vulnscan --list-profiles | --list-tools | --dry-run | --version

SAFE BY DEFAULT — detection, recon and *controlled* validation only. No
auto-exploitation, no post-exploitation, no DoS/flooding. Intrusive/destructive
capabilities require an explicit, authorized policy and never run by default.
This is an authorized-testing tool: only assess systems you own or are
explicitly permitted to test.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone

from core import __version__
from core import capabilities, config
from core.orchestrator import build_plan, run as run_assessment
from core.policy import Policy
from core.scope import Scope
from core.target_detector import KIND_TO_SCANNER, detect

try:
    from common import C
except Exception:                       # minimal color fallback
    class C:  # type: ignore
        RESET = BOLD = RED = GRN = YEL = BLU = CYN = MAG = ""

BANNER = r"""
╔══════════════════════════════════════════════╗
║            VULNSCAN SECURITY ENGINE            ║
╚══════════════════════════════════════════════╝"""

PROFILE_MENU = [
    ("bugbounty", "Bug Bounty (scope-first attack surface)"),
    ("redteam", "Red Team (authorized adversary emulation)"),
    ("enterprise", "Enterprise (broad internal assessment)"),
    ("web", "Web application / API"),
    ("mobile", "Mobile app (APK/IPA)"),
    ("cloud", "Cloud / IaC"),
    ("network", "Network / host"),
    ("code", "Source code"),
]


# ---------------------------------------------------------------------------
# informational commands
# ---------------------------------------------------------------------------
def cmd_list_profiles() -> int:
    print("Available profiles:")
    for name in config.list_profiles():
        p = config.load_profile(name)
        print(f"  {name:12} {p.get('description', '')}")
    return 0


def cmd_list_tools() -> int:
    snap = capabilities.snapshot()
    print(f"Tools available ({len(snap['available'])}):")
    for t in snap["available"]:
        print(f"  ✓ {t['name']:14} risk={t['risk']:11} kinds={','.join(t['kinds'])}"
              + (f"  [{t.get('version','')}]" if t.get("version") else ""))
    print(f"\nTools NOT installed ({len(snap['unavailable'])}):")
    for t in snap["unavailable"]:
        print(f"  ✗ {t['name']:14} kinds={','.join(t['kinds'])}")
    return 0


def cmd_list_capabilities() -> int:
    from core.policy import SAFETY_LEVELS
    print("Safety levels (least -> most impactful):", " -> ".join(SAFETY_LEVELS))
    print("Default policy runs: passive + safe_active only.\n")
    kinds = sorted({k for t in capabilities.REGISTRY for k in t.kinds})
    for k in kinds:
        tools = [t.name for t in capabilities.for_kind(k)]
        print(f"  {k:12} : {', '.join(tools)}")
    try:
        from validation import registry
        print("\nValidation capabilities (id : risk : requires):")
        for c in registry.summary():
            print(f"  {c['id']:28} {c['risk']:20} {', '.join(c['requires'])}")
    except Exception:
        pass
    return 0


def cmd_list_knowledge() -> int:
    from core import knowledge
    print(knowledge.render())
    print("\n" + knowledge.render_coverage_matrix())
    return 0


def cmd_gap_analysis() -> int:
    from core import gap_analysis
    print(gap_analysis.render())
    return 0


# map a detected target kind -> the install.sh group that provides its tools
KIND_INSTALL_GROUP = {
    "web": "web", "api": "web", "recon": "recon", "network": "network",
    "mobile": "mobile", "cloud": "cloud", "container": "container",
    "kubernetes": "cloud", "code": "code",
}


def run_installer(groups: list[str]) -> int:
    """Run the bundled install.sh for the given groups (streams output live)."""
    import subprocess
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "install.sh")
    if not os.path.isfile(script):
        print(f"{C.RED}install.sh not found next to vulnscan.py{C.RESET}")
        return 1
    groups = groups or ["all"]
    print(f"{C.CYN}Running installer: install.sh {' '.join(groups)}{C.RESET}\n", flush=True)
    try:
        return subprocess.run(["bash", script, *groups]).returncode
    except FileNotFoundError:
        print(f"{C.RED}bash not found — run: ./install.sh {' '.join(groups)}{C.RESET}")
        return 1


def cmd_install(groups: list[str]) -> int:
    return run_installer(groups)


def missing_tools_for_kind(kind: str, mode: str, policy) -> list[str]:
    """Tools that would help this scan but are not installed/on PATH."""
    miss = []
    for t in capabilities.for_kind(kind):
        if mode not in t.modes:
            continue
        if not t.available():
            miss.append(t.name)
    return sorted(set(miss))


def cmd_update() -> int:
    import subprocess
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feeds", "update_feeds.py")
    if not os.path.isfile(script):
        print("feed updater not found"); return 1
    return subprocess.run([sys.executable, script]).returncode


# ---------------------------------------------------------------------------
# interactive selection
# ---------------------------------------------------------------------------
def prompt_profile() -> str:
    print(f"{C.CYN}{C.BOLD}Select profile:{C.RESET}")
    for i, (name, desc) in enumerate(PROFILE_MENU, 1):
        print(f"  {i}. {desc}")
    choice = input("Choice [1-8] (default 1): ").strip() or "1"
    try:
        return PROFILE_MENU[int(choice) - 1][0]
    except (ValueError, IndexError):
        return choice if choice in dict(PROFILE_MENU) else "bugbounty"


def prompt_mode() -> str:
    print(f"\n{C.CYN}{C.BOLD}Select mode:{C.RESET}\n  1. FAST (quick, safe)\n  2. DEEP (thorough)")
    return "deep" if input("Choice [1-2] (default 1): ").strip() == "2" else "fast"


# device/target menu -> (label, hint, forced kind, default profile)
DEVICE_MENU = [
    ("Website / web app",        "e.g. https://example.com",          "web",        "web"),
    ("API endpoint",             "e.g. https://api.example.com",      "api",        "web"),
    ("Bug-bounty domain (recon)","e.g. example.com",                  "recon",      "bugbounty"),
    ("Network / host / IP",      "e.g. 192.168.1.10 or 10.0.0.0/24",  "network",    "network"),
    ("Mobile app",               "path to .apk / .ipa",               "mobile",     "mobile"),
    ("Source code folder",       "path to a project dir",             "code",       "code"),
    ("Cloud / IaC",              "aws|azure|gcp or ./terraform",      "cloud",      "cloud"),
    ("Container image",          "e.g. nginx:1.21",                   "container",  "cloud"),
    ("Kubernetes manifests",     "path to k8s yaml dir",              "kubernetes", "cloud"),
    ("Linux host (export JSON)", "path to host export",               "linux",      "enterprise"),
    ("Windows host (export JSON)","path to host export",              "windows",    "enterprise"),
]


def wizard():
    """Interactive one-command flow: ask device type -> target -> mode.
    Returns (target, forced_kind, profile, mode)."""
    print(BANNER)
    print(f"{C.CYN}{C.BOLD}What do you want to scan?{C.RESET}")
    for i, (label, hint, _k, _p) in enumerate(DEVICE_MENU, 1):
        print(f"  {i:2}. {label:26} {C.BLU}{hint}{C.RESET}")
    try:
        raw = input("\nChoice [1-11] (default 1): ").strip() or "1"
        idx = int(raw) - 1 if raw.isdigit() else 0
        idx = idx if 0 <= idx < len(DEVICE_MENU) else 0
        label, hint, kind, profile = DEVICE_MENU[idx]
        target = input(f"\nEnter target ({hint}): ").strip()
        mode = prompt_mode()
    except (EOFError, KeyboardInterrupt):
        return "", None, "", "fast"
    return target, kind, profile, mode


def authorize(target: str, profile: str, mode: str, policy: Policy, auto_yes: bool) -> bool:
    print(BANNER)
    print(f"Target : {C.BOLD}{target}{C.RESET}")
    print(f"Profile: {profile}    Mode: {mode.upper()}")
    print(f"Policy : {policy.summary()}")
    if auto_yes:
        return True
    print(f"\n{C.YEL}{C.BOLD}AUTHORIZATION REQUIRED{C.RESET}")
    print("Only assess systems you OWN or are EXPLICITLY authorized to test.")
    if policy.intrusive or policy.destructive:
        print(f"{C.RED}This policy permits INTRUSIVE/DESTRUCTIVE tests — be certain of authorization.{C.RESET}")
    return input("Type 'I AM AUTHORIZED' to continue: ").strip() == "I AM AUTHORIZED"


# ---------------------------------------------------------------------------
def collect_secrets(args) -> list[str]:
    """Gather operator-supplied secret values so they can be redacted from output."""
    secrets = []
    for v in (args.token, args.api_key, args.cookie):
        if v:
            secrets.append(v)
    for h in (args.header or []):
        if ":" in h:
            secrets.append(h.split(":", 1)[1].strip())
    return [s for s in secrets if s]


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="vulnscan",
        description="Universal Security Assessment & Authorized Adversary-Emulation platform. "
                    "Safe by default; authorized use only.")
    ap.add_argument("target", nargs="?", default=None, help="URL/domain/IP/CIDR/app/dir/image (omit for interactive)")
    ap.add_argument("--profile", default=None, help="assessment profile (see --list-profiles)")
    ap.add_argument("--mode", choices=["fast", "deep"], default=None, help="fast (quick) or deep (thorough)")
    ap.add_argument("--type", dest="force_kind",
                    choices=sorted(set(KIND_TO_SCANNER)), default=None,
                    help="force target kind (override auto-detection)")
    ap.add_argument("--scope", default=None, help="scope file (in-scope assets, one per line)")
    ap.add_argument("--program", default=None,
                    help="bug-bounty program config (YAML): scope + required headers + rate limit + "
                         "out-of-scope finding rules. The engine auto-respects all of it.")
    ap.add_argument("--policy", default=None, help="policy YAML file (safety levels)")
    ap.add_argument("--out", default=None, help="output directory")
    ap.add_argument("--formats", default="md,json,html", help="report formats: md,json,csv,html,pdf,sarif")
    ap.add_argument("--bundle", action="store_true",
                    help="write a professional report bundle (reports/: executive+technical, "
                         "json artifacts, evidence/, sarif, pdf)")
    ap.add_argument("--skip", default="", help="comma list of tools to skip")
    ap.add_argument("--deep", action="store_true", help="alias for --mode deep")
    ap.add_argument("--workers", type=int, default=None, help="max concurrent workers")
    ap.add_argument("--timeout", type=int, default=None, help="per-tool timeout seconds")
    # authentication (redacted from all output)
    ap.add_argument("--cookie", default=None)
    ap.add_argument("--header", action="append", help="extra header 'Name: value' (repeatable)")
    ap.add_argument("--token", default=None)
    ap.add_argument("--api-key", dest="api_key", default=None)
    ap.add_argument("--username", default=None)
    ap.add_argument("--aws-profile", dest="aws_profile", default=None)
    ap.add_argument("--gcp-project", dest="gcp_project", default=None)
    ap.add_argument("--azure-subscription", dest="azure_subscription", default=None)
    # baseline / retest / triage
    ap.add_argument("--compare", default=None, help="compare against an old report.json")
    ap.add_argument("--baseline", action="store_true", help="save this run as the baseline")
    ap.add_argument("--retest", action="store_true",
                    help="compare against the saved baseline for this target (auto-located)")
    ap.add_argument("--load-test", dest="load_test", action="store_true",
                    help="bounded, LAB-only availability load-test (opt-in; requires lab policy + dos.enabled; "
                         "hard-capped, rate-limited, abortable — never a DoS/flood)")
    ap.add_argument("--triage-file", dest="triage_file", default=None,
                    help="persistent triage store (fingerprint->status) applied across scans")
    ap.add_argument("--mark", default=None,
                    help="record a triage decision: 'FINGERPRINT=STATUS[:note]' (needs --triage-file)")
    ap.add_argument("--no-plugins", action="store_true", help="disable plugin loading")
    ap.add_argument("--resume", default=None, help="resume a previous scan by scan-id (no rescanning)")
    # CI gating (exit non-zero to fail a pipeline)
    ap.add_argument("--fail-on", dest="fail_on", default=None,
                    choices=["critical", "high", "medium", "low", "info"],
                    help="exit non-zero if any active finding is at/above this severity")
    ap.add_argument("--fail-on-kev", dest="fail_on_kev", action="store_true",
                    help="exit non-zero if any actively-exploited (CISA KEV) finding is present")
    ap.add_argument("--fail-on-new", dest="fail_on_new", action="store_true",
                    help="exit non-zero if new findings vs --compare baseline (needs --compare)")
    # Phase 3: identity + threat analysis from authorized data exports
    ap.add_argument("--identity-file", dest="identity_file", default=None,
                    help="identity graph export (JSON) for AD/cloud privilege-escalation analysis")
    ap.add_argument("--threat-input", dest="threat_file", default=None,
                    help="authorized host/cloud data export (JSON) for threat-indicator detection")
    ap.add_argument("--ioc-file", dest="ioc_file", default=None,
                    help="IOC feed (JSON: hashes/domains/ips) used with --threat-input")
    ap.add_argument("--telemetry", dest="telemetry_file", default=None,
                    help="SIEM/EDR/IDS detections export (JSON) for purple-team detection verification")
    ap.add_argument("--se-input", dest="se_file", default=None,
                    help="authorized awareness-campaign RESULTS (JSON) for social-engineering analysis "
                         "(requires social_engineering enabled in policy; analysis only, no sending)")
    # meta
    ap.add_argument("--yes", action="store_true", help="skip authorization prompt (owned assets/CI)")
    ap.add_argument("--dry-run", action="store_true", help="show the planned pipeline, run nothing")
    ap.add_argument("--coverage", action="store_true", help="print coverage summary only")
    ap.add_argument("--list-profiles", action="store_true")
    ap.add_argument("--list-tools", action="store_true")
    ap.add_argument("--list-capabilities", action="store_true")
    ap.add_argument("--list-knowledge", action="store_true",
                    help="show the security-knowledge catalog (families, counts, domain coverage)")
    ap.add_argument("--gap-analysis", dest="gap_analysis", action="store_true",
                    help="show the capability/gap matrix derived from code (knowledge→detection→"
                         "validation→checker), incl. honest manual/uncovered gaps")
    ap.add_argument("--install", nargs="*", metavar="GROUP", default=None,
                    help="install all external scanners in one shot, then exit "
                         "(optionally limit to groups: recon web network mobile cloud code container)")
    ap.add_argument("--auto-install", dest="auto_install", action="store_true",
                    help="before scanning, auto-install any missing tools for the target's kind "
                         "(runs install.sh for that group; needs sudo/network)")
    ap.add_argument("--check-updates", action="store_true")
    ap.add_argument("--update", action="store_true", help="refresh CVE feeds")
    ap.add_argument("--version", action="store_true")
    args = ap.parse_args()

    # meta commands
    if args.version:
        print(f"vulnscan {__version__}")
        return 0
    if args.list_profiles:
        return cmd_list_profiles()
    if args.list_tools:
        return cmd_list_tools()
    if args.list_capabilities:
        return cmd_list_capabilities()
    if args.list_knowledge:
        return cmd_list_knowledge()
    if args.gap_analysis:
        return cmd_gap_analysis()
    if args.install is not None:
        return cmd_install(args.install)
    if args.update or args.check_updates:
        return cmd_update()

    # resume a previous scan from its checkpoint (no rescanning)
    if args.resume:
        from core.orchestrator import resume_scan
        from reporting import report as report_mod
        a = resume_scan(args.resume)
        if a is None:
            print(f"No checkpoint found for scan-id '{args.resume}'."); return 2
        outdir = args.out or f"report-resume-{args.resume}"
        paths = report_mod.write_all(a, outdir, formats=tuple(f.strip() for f in args.formats.split(",") if f.strip()))
        print("\n" + a.coverage.render())
        s = report_mod.summarize(a)
        print(f"\nRESUMED {args.resume}: score {s['security_score']}/100 | findings {s['total']} | "
              f"attack-paths {s['attack_paths']}")
        for fmt, p in paths.items():
            print(f"  report.{fmt}: {p}")
        return 0

    # record a triage decision and exit
    if args.mark:
        if not args.triage_file:
            print("--mark requires --triage-file"); return 2
        from core.triage import TriageStore
        spec, _, rest = args.mark.partition("=")
        status, _, note = rest.partition(":")
        store = TriageStore.load(args.triage_file)
        try:
            store.mark(spec.strip(), status.strip(), note.strip())
        except ValueError as e:
            print(e); return 2
        store.save()
        print(f"triage: {spec.strip()} -> {status.strip()}  (saved {args.triage_file})")
        return 0

    # target + profile + mode (interactive wizard if no target given)
    target = args.target
    profile = (args.profile or "").lower()
    force_kind = args.force_kind
    mode = args.mode
    if not target:
        # one-command interactive flow: asks device type -> target -> mode
        target, wk, wp, wm = wizard()
        force_kind = force_kind or wk
        profile = profile or wp
        mode = mode or wm
    else:
        if not profile:
            # infer a sensible default profile from the detected kind
            kind = force_kind or detect(target)["kind"]
            profile = {"recon": "bugbounty", "web": "web", "api": "web", "network": "network",
                       "mobile": "mobile", "cloud": "cloud", "container": "cloud",
                       "kubernetes": "cloud", "code": "code", "linux": "enterprise",
                       "windows": "enterprise"}.get(kind, "bugbounty")
        mode = mode or ("deep" if args.deep else config.load_profile(profile).get("default_mode", "fast"))
    if not target:
        print("No target given."); return 2
    if not mode:
        mode = "deep" if args.deep else "fast"

    policy = config.load_policy(profile, mode, args.policy)
    if args.workers:
        policy.workers = args.workers
    if args.timeout:
        policy.timeout = args.timeout
    if args.skip:
        policy.excluded_tools += [s.strip() for s in args.skip.split(",") if s.strip()]

    # dry-run: show plan and exit
    if args.dry_run:
        plan = build_plan(target, profile, mode, policy)
        if force_kind:
            plan["kind"] = force_kind
            plan["scanner"] = KIND_TO_SCANNER.get(force_kind, plan["scanner"])
        print(BANNER)
        print(f"DRY RUN — no tests will be executed\n")
        print(f"Target   : {target}")
        print(f"Detected : {plan['kind']}  ->  {plan['scanner']}")
        print(f"Profile  : {profile}   Mode: {mode}")
        print(f"Policy   : {policy.summary()}")
        print(f"Tools selected : {', '.join(plan['tools_selected']) or '(none installed/allowed)'}")
        print("Tools skipped  :")
        for t, r in sorted(plan["tools_skipped"].items()):
            print(f"    - {t}: {r}")
        return 0

    # tool availability: auto-install (opt-in) or nudge with the one command to fix it
    kind_for_tools = force_kind or detect(target)["kind"]
    grp = KIND_INSTALL_GROUP.get(kind_for_tools)
    miss = missing_tools_for_kind(kind_for_tools, mode, policy)
    if args.auto_install and grp and miss:
        print(f"{C.YEL}Missing tools for {kind_for_tools}: {', '.join(miss)} — installing now…{C.RESET}")
        run_installer([grp])
        miss = missing_tools_for_kind(kind_for_tools, mode, policy)  # re-check
    if miss:
        g = grp or "all"
        shown = ", ".join(miss[:6]) + ("…" if len(miss) > 6 else "")
        print(f"{C.YEL}Note: {len(miss)} tool(s) not installed ({shown}).{C.RESET}")
        print(f"{C.YEL}      Install them all in one shot: {C.BOLD}python3 vulnscan.py --install {g}{C.RESET}"
              + ("" if args.auto_install else f"  {C.YEL}(or add --auto-install){C.RESET}"))

    if not authorize(target, profile, mode, policy, args.yes):
        print("Authorization not confirmed. Aborting."); return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", target)[:40]
    outdir = args.out or f"report-{profile}-{safe}-{ts}"
    secrets = collect_secrets(args)

    triage_store = None
    if args.triage_file:
        from core.triage import TriageStore
        triage_store = TriageStore.load(args.triage_file)

    assessment = run_assessment(
        target, profile=profile, mode=mode, policy=policy,
        outdir=outdir, scope_file=args.scope, secrets=secrets, force_kind=force_kind,
        triage_store=triage_store, load_plugins=not args.no_plugins,
        identity_file=args.identity_file, threat_file=args.threat_file, ioc_file=args.ioc_file,
        telemetry_file=args.telemetry_file, se_file=args.se_file, load_test=args.load_test,
        program_file=args.program)

    # reports
    from reporting import report as report_mod
    formats = tuple(f.strip() for f in args.formats.split(",") if f.strip())
    paths = report_mod.write_all(assessment, outdir, formats=formats)
    if args.bundle:
        from reporting import bundle as bundle_mod
        bpaths = bundle_mod.write_bundle(assessment, outdir)
        paths["bundle"] = os.path.join(outdir, "reports")

    # console output
    print("\n" + assessment.coverage.render())
    try:
        from core import knowledge as _kn
        print("\n" + _kn.render_coverage_matrix(assessment.findings))
    except Exception:
        pass
    s = report_mod.summarize(assessment)
    print(f"\n{C.BOLD}RESULT{C.RESET}: score {s['security_score']}/100 | "
          f"crit {s['counts']['critical']} high {s['counts']['high']} med {s['counts']['medium']} "
          f"low {s['counts']['low']} info {s['counts']['info']} | KEV {s['kev_count']} | "
          f"attack-paths {s['attack_paths']}")
    if assessment.scan_id:
        print(f"Scan ID: {assessment.scan_id}  (resume with: --resume {assessment.scan_id})")
    if assessment.out_of_scope_dropped:
        print(f"{C.YEL}Out-of-scope assets dropped: {len(assessment.out_of_scope_dropped)}{C.RESET}")
    if assessment.social:
        try:
            from social_engineering.simulation import render as _serender
            print("\n" + _serender({"metrics": assessment.social}))
        except Exception:
            pass
    if assessment.detection:
        try:
            from purple.verification import render as _drender
            print("\n" + _drender(assessment.detection))
        except Exception:
            ds = assessment.detection.get("summary", {})
            print(f"{C.MAG}Detection verification: {ds.get('detected', 0)}/"
                  f"{ds.get('techniques_considered', 0)} detected, {ds.get('gaps', 0)} gap(s){C.RESET}")
    for fmt, p in paths.items():
        print(f"  report.{fmt}: {p}")

    # baseline / compare / retest
    compare_diff = None
    from core import checkpoint as _ckpt
    compare_path = args.compare
    if args.retest and not compare_path:
        compare_path = _ckpt.find_baseline(target)
        if not compare_path:
            print(f"{C.YEL}--retest: no saved baseline for this target yet; "
                  f"run once with --baseline first.{C.RESET}")
    if compare_path:
        from reporting import compare as cmp_mod
        try:
            compare_diff = cmp_mod.compare(compare_path, assessment)
            print("\n" + cmp_mod.render(compare_diff))
        except Exception as e:
            print(f"compare failed: {e}")
    # always refresh the target's baseline after a retest so trend continues
    if args.retest:
        _ckpt.save_baseline(target, paths.get("json", os.path.join(outdir, "report.json")))
    if args.baseline:
        import shutil
        base = os.path.join(outdir, "baseline.json")
        rep_json = paths.get("json", os.path.join(outdir, "report.json"))
        shutil.copy(rep_json, base)
        # also persist to the target's baseline store so --retest can auto-locate it
        stored = _ckpt.save_baseline(target, rep_json)
        print(f"  baseline saved: {base}" + (f" (+ retest store: {stored})" if stored else ""))

    # CI gating (exit non-zero to fail a pipeline)
    if args.fail_on or args.fail_on_kev or args.fail_on_new:
        from reporting.sarif import gate
        code, reason = gate(assessment, fail_on=args.fail_on, fail_on_kev=args.fail_on_kev,
                            fail_on_new=args.fail_on_new, compare_diff=compare_diff)
        print(f"\n{(C.RED if code else C.GRN)}{reason}{C.RESET}")
        return code
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted"); sys.exit(130)
