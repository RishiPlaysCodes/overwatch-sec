#!/usr/bin/env python3
"""
core/orchestrator.py — the assessment brain.

Given (target, profile, mode, policy, scope) it:
  1. detects the target kind,
  2. selects the right scanner pipeline,
  3. translates policy + mode into which tools may run (safe by default),
  4. runs the existing scanner_*.py modules (preserved, not rewritten),
  5. normalizes their findings into the unified Finding model,
  6. enforces scope on discovered assets/findings,
  7. correlates findings into attack paths + maps MITRE ATT&CK,
  8. tracks measurable coverage.

It never runs intrusive/destructive tests unless the Policy explicitly allows
them — and destructive is refused unless authorization is lab/red_team.
"""

from __future__ import annotations

import importlib
import os
import time
from dataclasses import dataclass, field

from . import capabilities, coverage as cov_mod
from .findings import Finding, dedupe, sort_key
from .policy import Policy
from .scope import Scope
from .target_detector import KIND_TO_SCANNER, detect

_RISK_RANK = {"passive": 0, "safe_active": 1, "validation": 2, "intrusive": 3, "destructive": 4}


@dataclass
class Assessment:
    target: str
    kind: str
    profile: str
    mode: str
    policy: Policy
    scope: Scope
    findings: list = field(default_factory=list)          # list[Finding]
    attack_paths: list = field(default_factory=list)
    coverage: object = None
    scanner: str = ""
    out_of_scope_dropped: list = field(default_factory=list)
    plan: dict = field(default_factory=dict)
    detection: dict = field(default_factory=dict)   # purple-team detection verification
    social: dict = field(default_factory=dict)      # social-engineering simulation metrics
    program: str = ""                               # program-config summary (bug bounty)
    scan_id: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "kind": self.kind,
            "profile": self.profile,
            "mode": self.mode,
            "policy": self.policy.summary(),
            "scope": self.scope.describe(),
            "scanner": self.scanner,
            "findings": [f.to_dict() for f in self.findings],
            "attack_paths": self.attack_paths,
            "out_of_scope_dropped": self.out_of_scope_dropped,
            "detection": self.detection,
            "social": self.social,
            "program": self.program,
            "scan_id": self.scan_id,
            "coverage": self.coverage.summary() if self.coverage else {},
        }


def _tool_allowed(tool: capabilities.Tool, policy: Policy, mode: str) -> tuple[bool, str]:
    """Decide if a tool may run under this policy+mode. Returns (allowed, reason)."""
    if not policy.allows_tool(tool.name):
        return False, "policy_disallowed"
    if mode not in tool.modes:
        return False, "mode_excluded"
    if not policy.allows_level(tool.risk):
        return False, "unsafe_or_destructive"
    return True, ""


def build_plan(target: str, profile: str, mode: str, policy: Policy) -> dict:
    """Compute the pipeline WITHOUT running it (for --dry-run)."""
    desc = detect(target)
    kind = desc["kind"]
    scanner = KIND_TO_SCANNER.get(kind, "scanner_web")
    tools_selected, tools_skipped = [], {}
    for t in capabilities.for_kind(kind):
        ok, reason = _tool_allowed(t, policy, mode)
        if not t.available():
            tools_skipped[t.name] = "tool_missing"
        elif ok:
            tools_selected.append(t.name)
        else:
            tools_skipped[t.name] = reason
    return {
        "target": target, "kind": kind, "scanner": scanner,
        "profile": profile, "mode": mode, "policy": policy.summary(),
        "tools_selected": tools_selected, "tools_skipped": tools_skipped,
    }


def _skip_set(kind: str, mode: str, policy: Policy, scope_file: str | None) -> set:
    """Translate policy+mode into the `skip` set the legacy scanners understand."""
    skip: set[str] = set(policy.excluded_tools)
    if mode == "deep":
        skip.add("__deep__")
    if scope_file:
        skip.add(f"scope={scope_file}")
    # policy-driven tool gating: skip any tool the policy/mode disallows
    for t in capabilities.for_kind(kind):
        ok, _ = _tool_allowed(t, policy, mode)
        if not ok:
            skip.add(t.name)
            # legacy recon uses "nmap-vuln" gate too
    return skip


def run(target: str, profile: str = "bugbounty", mode: str = "fast",
        policy: Policy | None = None, scope: Scope | None = None,
        outdir: str = "report", scope_file: str | None = None,
        secrets: list[str] | None = None, force_kind: str | None = None,
        triage_store=None, load_plugins: bool = True,
        identity_file: str | None = None, threat_file: str | None = None,
        ioc_file: str | None = None, telemetry_file: str | None = None,
        scan_id: str | None = None, se_file: str | None = None,
        load_test: bool = False, program_file: str | None = None) -> Assessment:
    # extensibility: load drop-in plugins before detection/registry use
    if load_plugins:
        try:
            from . import plugins
            plugins.load_plugins()
        except Exception:
            pass
    policy = policy or Policy.for_profile(profile, mode)
    desc = detect(target)
    kind = force_kind or desc["kind"]

    # program config: sets required headers + rate limit + scope + OOS finding rules
    program = None
    if program_file:
        try:
            from . import program as _prog
            program = _prog.load(program_file)
            if program:
                _prog.apply_to_request_context(program)   # headers + throttle on ALL traffic
        except Exception:
            program = None

    if scope is None:
        if program and not program.scope.is_empty():
            scope = program.scope
        elif scope_file:
            scope = Scope.from_file(scope_file)
        else:
            scope = Scope.single(target)
    scanner_mod = KIND_TO_SCANNER.get(kind, "scanner_web")

    cov = cov_mod.Coverage()
    try:
        import knowledgebase as kb
        cov.kb_version = f"{len(kb.KB)} entries"
    except Exception:
        pass
    # feed freshness
    try:
        manifest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "manifest.json")
        if os.path.isfile(manifest):
            import json
            cov.feeds_updated = json.load(open(manifest)).get("updated_at", "")
    except Exception:
        pass

    _program_obj = program  # keep ref for the loop below
    assessment = Assessment(target=target, kind=kind, profile=profile, mode=mode,
                            policy=policy, scope=scope, scanner=scanner_mod, coverage=cov)
    assessment.plan = build_plan(target, profile, mode, policy)
    if program:
        assessment.program = program.summary()

    # checkpoint (progress is persisted so a crash doesn't lose everything)
    from .checkpoint import Checkpoint, new_scan_id
    sid = scan_id or new_scan_id(target)
    assessment.scan_id = sid
    cp = Checkpoint(sid, {"target": target, "profile": profile, "mode": mode, "kind": kind})
    cp.mark("scan", "running")

    # tool availability -> coverage
    for t in capabilities.for_kind(kind):
        (cov.tools_executed if t.available() and t.name in assessment.plan["tools_selected"]
         else cov.tools_unavailable).append(t.name if not t.available() else t.name)
    cov.tools_unavailable = [t.name for t in capabilities.for_kind(kind) if not t.available()]

    os.makedirs(outdir, exist_ok=True)
    skip = _skip_set(kind, mode, policy, scope_file)

    # run the selected scanner pipeline
    t0 = time.time()
    try:
        mod = importlib.import_module(scanner_mod)
        raw = mod.scan(target, outdir, skip)
        cov.ran(scanner_mod, detail=f"kind={kind}", seconds=round(time.time() - t0, 1))
    except Exception as e:  # never crash the whole assessment on one scanner
        cov.errored(scanner_mod, detail=str(e)[:200])
        raw = {"findings": [], "tools": []}

    # record tool execution reported by the scanner
    for t in raw.get("tools", []):
        status = t.get("status", "")
        if status.startswith("skip"):
            cov.tools_unavailable.append(t.get("tool", "?"))
        else:
            cov.tools_executed.append(t.get("tool", "?"))

    # repo-level CI/CD + IaC static analysis (dependency-free) for local directories.
    # scanner_code already runs these for 'code' targets; run them here for cloud/
    # kubernetes/container dir targets so a repo gets CI/CD + IaC coverage regardless
    # of how the directory was classified. dedupe() removes any overlap.
    if kind in ("cloud", "kubernetes", "container") and os.path.isdir(target):
        for amod, label in (("analyzers.cicd", "cicd_analysis"), ("analyzers.iac", "iac_analysis")):
            try:
                m = importlib.import_module(amod)
                extra = m.analyze_dir(target)
                raw.setdefault("findings", []).extend(extra)
                cov.ran(label, detail=f"{len(extra)} finding(s)")
            except Exception as e:
                cov.errored(label, detail=str(e)[:120])

    # availability & resilience assessment (safe, passive) for network-facing web/api
    if kind in ("web", "api", "recon"):
        try:
            from validation import resilience
            ra = resilience.assess(target)
            raw.setdefault("findings", []).extend(ra)
            cov.ran("availability_assessment", detail=f"{len(ra)} signal(s)")
        except Exception as e:
            cov.errored("availability_assessment", detail=str(e)[:120])
        # bounded, opt-in, LAB-only load-test (off by default; refuses unless authorized)
        if load_test:
            try:
                from validation import loadtest
                lt = loadtest.run(target, policy, opt_in=True)
                raw.setdefault("findings", []).extend(lt)
                cov.ran("availability_loadtest", detail=f"{len(lt)} signal(s)")
            except Exception as e:
                cov.errored("availability_loadtest", detail=str(e)[:120])

    # scope only applies to network-facing targets; local artifacts (code/cloud
    # IaC dir / container image / k8s manifests / mobile files) have no "scope".
    scope_enforced = kind in ("recon", "web", "api", "network") or (kind == "cloud" and target in ("aws", "azure", "gcp"))

    # normalize + scope-enforce findings
    findings: list[Finding] = []
    for d in raw.get("findings", []):
        asset = d.get("asset") or _guess_asset(d, target)
        f = Finding.from_legacy(d, asset=asset, profile=profile)
        if scope_enforced and scope and asset and not scope.allows(asset):
            assessment.out_of_scope_dropped.append(asset)
            continue
        # redact any operator secrets from evidence before it is ever stored
        if secrets:
            from .policy import redact
            f.evidence = redact(f.evidence, secrets)
        # program rules: mark finding types the program declares out-of-scope /
        # not-rewarded so they don't pollute the actionable results (kept, labelled).
        if program:
            if program.is_out_of_scope_finding(f.id):
                f.status = "accepted_risk"     # excluded from score/gating, shown separately
                f.tags.append("program:out-of-scope")
            elif program.is_focus_finding(f.id):
                f.tags.append("program:focus")
        findings.append(f)
    findings = dedupe(findings)

    # optional: identity/AD/cloud attack-path analysis from an authorized export.
    # Accepts either our native identity schema OR a raw BloodHound export
    # (auto-converted by connectors.detect_and_load).
    if identity_file:
        try:
            from attack_paths import identity
            kind_c, data_c = _try_connector(identity_file)
            if kind_c == "identity":
                idf = identity.analyze(data_c)
            else:
                idf = identity.load_and_analyze(identity_file)
            findings += idf
            cov.ran("identity_analysis", detail=f"{len(idf)} escalation path(s)")
        except Exception as e:
            cov.errored("identity_analysis", detail=str(e)[:150])

    # optional: threat-detection / cloud findings from an authorized export.
    # Accepts our native threat schema OR raw ScoutSuite/Prowler output.
    if threat_file:
        try:
            from threat_detection import detector
            kind_c, data_c = _try_connector(threat_file)
            if kind_c == "findings":     # e.g. Prowler -> ready-made Finding objects
                findings += data_c
                cov.ran("cloud_findings_import", detail=f"{len(data_c)} finding(s)")
            elif kind_c == "threat":     # e.g. ScoutSuite -> threat telemetry
                tf = detector.analyze_input(data_c, _load_json(ioc_file))
                findings += tf
                cov.ran("threat_detection", detail=f"{len(tf)} indicator(s)")
            else:                         # native threat-input schema
                tf = detector.load_and_analyze(threat_file, ioc_file)
                findings += tf
                cov.ran("threat_detection", detail=f"{len(tf)} indicator(s)")
        except Exception as e:
            cov.errored("threat_detection", detail=str(e)[:150])

    findings = dedupe(findings)

    # authorized social-engineering awareness simulation (analysis only; gated by policy)
    if se_file:
        if getattr(policy, "social_engineering", False):
            try:
                from social_engineering import simulation
                se = simulation.load_and_analyze(se_file)
                findings += se.get("findings", [])
                assessment.social = se.get("metrics", {})
                cov.ran("social_engineering", detail=f"human_risk={assessment.social.get('human_risk_score')}")
            except Exception as e:
                cov.errored("social_engineering", detail=str(e)[:120])
        else:
            cov.skipped("social_engineering", "policy_disallowed",
                        "enable social_engineering in the policy to include awareness metrics")

    cp.store_findings(findings)
    cp.mark("collect", "completed", f"{len(findings)} findings")

    # safe, policy-gated validation (upgrades detected -> validated / not_exploitable /
    # not_validated / manual / blocked_by_*), driven by the capability registry.
    try:
        from validation import validator
        vctx = {"has_auth": bool(secrets), "in_scope": True}
        cov.validation_stats = validator.validate(findings, policy, coverage=cov, context=vctx)
        cp.store_findings(findings)
        cp.mark("validate", "completed")
    except Exception as e:
        cov.errored("validation", detail=str(e)[:150])
        cp.mark("validate", "failed", str(e)[:120])

    # attack-path correlation + MITRE mapping
    try:
        from attack_paths import correlation, mitre
        mitre.annotate(findings)
        assessment.attack_paths = correlation.build_paths(findings, target)
        cov.attack_techniques = len({m for f in findings for m in f.mitre})
    except Exception as e:
        cov.errored("attack_paths", detail=str(e)[:150])

    # purple-team detection verification (always available; run for the purple
    # profile or whenever a telemetry export is supplied)
    if profile == "purple" or telemetry_file:
        try:
            from purple import verification
            assessment.detection = verification.load_and_verify(findings, telemetry_file)
            cov.ran("detection_verification",
                    detail=f"gaps={assessment.detection['summary']['gaps']}")
        except Exception as e:
            cov.errored("detection_verification", detail=str(e)[:150])

    # overlay persistent triage decisions (false_positive / accepted_risk / fixed)
    if triage_store is not None:
        try:
            applied = triage_store.apply(findings)
            if applied:
                cov.ran("triage", detail=f"applied {applied} stored decision(s)")
        except Exception as e:
            cov.errored("triage", detail=str(e)[:120])

    cov.checks_run = len(raw.get("findings", []))
    findings.sort(key=sort_key)
    assessment.findings = findings
    cp.store_findings(findings)
    cp.mark("report", "completed", f"score-ready, {len(findings)} findings")
    return assessment


def resume_scan(scan_id: str) -> Assessment | None:
    """
    Rebuild an assessment from a saved checkpoint WITHOUT rescanning (spec §22).
    Restores the findings gathered/validated before the interruption and
    re-derives attack paths + detection verification (cheap, deterministic).
    """
    from .checkpoint import Checkpoint
    from .policy import Policy
    from .scope import Scope
    cp = Checkpoint.load(scan_id)
    if cp is None:
        return None
    meta = cp.meta or {}
    findings = cp.restore_findings()
    cov = cov_mod.Coverage()
    cov.ran("resume", detail=f"restored {len(findings)} findings from {scan_id} "
                             f"(stages: {cp.summary()['stages']})")
    a = Assessment(target=meta.get("target", ""), kind=meta.get("kind", "web"),
                   profile=meta.get("profile", "bugbounty"), mode=meta.get("mode", "fast"),
                   policy=Policy.for_profile(meta.get("profile", "bugbounty"), meta.get("mode", "fast")),
                   scope=Scope.single(meta.get("target", "")), coverage=cov, scan_id=scan_id)
    try:
        from attack_paths import correlation, mitre
        mitre.annotate(findings)
        a.attack_paths = correlation.build_paths(findings, a.target)
        cov.attack_techniques = len({m for f in findings for m in f.mitre})
    except Exception as e:
        cov.errored("attack_paths", detail=str(e)[:120])
    findings.sort(key=sort_key)
    a.findings = findings
    return a


def _try_connector(path: str):
    """Return (kind, data) from a raw tool export, or (None, None) if native."""
    try:
        from connectors import detect_and_load
        return detect_and_load(path)
    except Exception:
        return None, None


def _load_json(path):
    if not path:
        return None
    try:
        import json
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


def _guess_asset(d: dict, target: str) -> str:
    """
    Best-effort asset for a legacy finding. Prefer a URL/domain found in the
    evidence; otherwise fall back to the target *preserving its scheme* so
    validators can safely re-request it (http vs https matters).
    """
    import re
    ev = d.get("evidence", "")
    m = re.search(r"https?://[^\s'\"]+", ev)
    if m:
        return m.group(0)
    m = re.search(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", ev, re.I)
    if m:
        return m.group(1)
    return target
