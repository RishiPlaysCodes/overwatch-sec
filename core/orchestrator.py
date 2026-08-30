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
        triage_store=None, load_plugins: bool = True) -> Assessment:
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
    scope = scope or (Scope.from_file(scope_file) if scope_file else Scope.single(target))
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

    assessment = Assessment(target=target, kind=kind, profile=profile, mode=mode,
                            policy=policy, scope=scope, scanner=scanner_mod, coverage=cov)
    assessment.plan = build_plan(target, profile, mode, policy)

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

    # normalize + scope-enforce findings
    findings: list[Finding] = []
    for d in raw.get("findings", []):
        asset = d.get("asset") or _guess_asset(d, target)
        f = Finding.from_legacy(d, asset=asset, profile=profile)
        if scope and asset and not scope.allows(asset):
            assessment.out_of_scope_dropped.append(asset)
            continue
        # redact any operator secrets from evidence before it is ever stored
        if secrets:
            from .policy import redact
            f.evidence = redact(f.evidence, secrets)
        findings.append(f)
    findings = dedupe(findings)

    # safe, policy-gated validation (upgrades detected -> validated / not_exploitable)
    try:
        from validation import validator
        validator.validate(findings, policy, coverage=cov)
    except Exception as e:
        cov.errored("validation", detail=str(e)[:150])

    # attack-path correlation + MITRE mapping
    try:
        from attack_paths import correlation, mitre
        mitre.annotate(findings)
        assessment.attack_paths = correlation.build_paths(findings, target)
        cov.attack_techniques = len({m for f in findings for m in f.mitre})
    except Exception as e:
        cov.errored("attack_paths", detail=str(e)[:150])

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
    return assessment


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
