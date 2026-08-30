#!/usr/bin/env python3
"""
core/coverage.py — measurable coverage + honesty tracking (spec §20).

The platform must never claim "100% secure" or "every attack tested". Instead
it records exactly what ran, what didn't, and WHY — so the report can show real,
measurable coverage with reasons for anything skipped.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

SKIP_REASONS = (
    "tool_missing", "platform_unsupported", "scope_restriction",
    "unsafe_or_destructive", "auth_unavailable", "insufficient_permissions",
    "mode_excluded", "policy_disallowed", "offline",
)


@dataclass
class Stage:
    name: str
    status: str = "pending"     # pending|ran|skipped|error
    reason: str = ""            # a SKIP_REASONS value when skipped
    detail: str = ""
    seconds: float = 0.0


@dataclass
class Coverage:
    started: float = field(default_factory=time.time)
    stages: list[Stage] = field(default_factory=list)
    tools_executed: list[str] = field(default_factory=list)
    tools_unavailable: list[str] = field(default_factory=list)
    checks_run: int = 0
    kb_version: str = ""
    feeds_updated: str = ""
    attack_techniques: int = 0
    # raw counts returned by validation/validator.validate() (spec §30).
    validation_stats: dict = field(default_factory=dict)

    def stage(self, name: str) -> Stage:
        s = Stage(name=name)
        self.stages.append(s)
        return s

    def ran(self, name: str, detail: str = "", seconds: float = 0.0) -> None:
        self.stages.append(Stage(name, "ran", "", detail, seconds))

    def skipped(self, name: str, reason: str, detail: str = "") -> None:
        self.stages.append(Stage(name, "skipped", reason, detail))

    def errored(self, name: str, detail: str = "") -> None:
        self.stages.append(Stage(name, "error", "", detail))

    def validation_coverage(self) -> dict:
        """
        Measurable validation coverage (spec §30), derived from the raw stats the
        validator returned. This answers "of the findings we could validate, how
        many did we actually confirm/refute, and why were the rest not run?" —
        honestly, with a reason for every not-run bucket. Never a security claim.
        """
        v = self.validation_stats or {}
        g = lambda k: int(v.get(k, 0))  # noqa: E731
        total = g("findings_total")
        selected = g("selected")
        validated = g("validated")
        refuted = g("not_exploitable")
        unvalidated = g("not_validated")
        manual = g("manual_validation_required")
        blocked_policy = g("blocked_by_policy")
        blocked_auth = g("blocked_by_authentication")
        blocked_dep = g("blocked_by_missing_dependency")
        blocked_scope = g("blocked_by_scope")
        errors = g("error")
        executed = validated + refuted + unvalidated + errors
        not_applicable = max(0, total - selected)
        resolved = validated + refuted
        # % of selected checks that produced a definitive confirm/refute
        rate = round(100 * resolved / selected) if selected else 0
        return {
            "findings_total": total,
            "selected": selected,
            "not_applicable": not_applicable,
            "executed": executed,
            "validated": validated,
            "not_exploitable": refuted,
            "unvalidated": unvalidated,
            "manual_required": manual,
            "blocked_by_policy": blocked_policy,
            "missing_prerequisite": blocked_auth + blocked_dep,
            "blocked_by_scope": blocked_scope,
            "errors": errors,
            "validation_rate": rate,
        }

    def summary(self) -> dict:
        ran = [s for s in self.stages if s.status == "ran"]
        skipped = [s for s in self.stages if s.status == "skipped"]
        errored = [s for s in self.stages if s.status == "error"]
        reasons: dict[str, int] = {}
        for s in skipped:
            reasons[s.reason] = reasons.get(s.reason, 0) + 1
        return {
            "elapsed_seconds": round(time.time() - self.started, 1),
            "stages_total": len(self.stages),
            "stages_ran": len(ran),
            "stages_skipped": len(skipped),
            "stages_errored": len(errored),
            "skip_reasons": reasons,
            "tools_executed": sorted(set(self.tools_executed)),
            "tools_unavailable": sorted(set(self.tools_unavailable)),
            "checks_run": self.checks_run,
            "attack_techniques_mapped": self.attack_techniques,
            "validation_coverage": self.validation_coverage(),
            "kb_version": self.kb_version,
            "feeds_updated": self.feeds_updated,
            "disclaimer": "Coverage is measurable, not exhaustive. This is not a claim of "
                          "'100% secure' — new vulnerabilities emerge continuously.",
        }

    def render(self) -> str:
        s = self.summary()
        lines = ["ASSESSMENT COVERAGE", ""]
        lines.append(f"  Stages ran/skipped/errored : {s['stages_ran']}/{s['stages_skipped']}/{s['stages_errored']}")
        lines.append(f"  Tools executed             : {len(s['tools_executed'])} ({', '.join(s['tools_executed']) or 'none'})")
        lines.append(f"  Tools unavailable          : {len(s['tools_unavailable'])}")
        lines.append(f"  ATT&CK techniques mapped   : {s['attack_techniques_mapped']}")
        vc = s.get("validation_coverage", {})
        if vc.get("selected"):
            lines.append("  Validation coverage:")
            lines.append(f"    - selected/executed      : {vc['selected']}/{vc['executed']} "
                         f"({vc['validation_rate']}% confirmed or refuted)")
            lines.append(f"    - validated / refuted    : {vc['validated']} / {vc['not_exploitable']}")
            lines.append(f"    - unvalidated / manual   : {vc['unvalidated']} / {vc['manual_required']}")
            not_run = []
            if vc["blocked_by_policy"]:
                not_run.append(f"policy {vc['blocked_by_policy']}")
            if vc["missing_prerequisite"]:
                not_run.append(f"missing-prereq {vc['missing_prerequisite']}")
            if vc["blocked_by_scope"]:
                not_run.append(f"scope {vc['blocked_by_scope']}")
            if vc["errors"]:
                not_run.append(f"errors {vc['errors']}")
            if not_run:
                lines.append(f"    - not run (with reason)  : {', '.join(not_run)}")
        if s["skip_reasons"]:
            lines.append("  Skipped because:")
            for r, n in sorted(s["skip_reasons"].items()):
                lines.append(f"    - {r}: {n}")
        if s.get("kb_version"):
            lines.append(f"  Knowledge base             : {s['kb_version']}")
        lines.append(f"  Elapsed                    : {s['elapsed_seconds']}s")
        lines.append("")
        lines.append("  NOTE: measurable coverage only — never '100% secure'.")
        return "\n".join(lines)
