#!/usr/bin/env python3
"""
core/policy.py — safety levels + authorization gate (SAFE BY DEFAULT).

Every test the platform can run is tagged with a SafetyLevel. A Policy decides
which levels are permitted for this engagement. The defaults are deliberately
conservative: passive + safe-active only; validation off; intrusive/destructive
off; DoS and social-engineering OFF and requiring explicit separate opt-in.

This is the guardrail that keeps the platform an *authorized assessment* tool
rather than an attack weapon: nothing intrusive or destructive can run unless
the operator explicitly turns it on for a target they're authorized to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Ordered least -> most impactful
SAFETY_LEVELS = ("passive", "safe_active", "validation", "intrusive", "destructive")
_LEVEL_RANK = {lvl: i for i, lvl in enumerate(SAFETY_LEVELS)}

# Engagement authorization contexts (spec §13)
AUTH_PROFILES = ("bug_bounty", "authorized_pentest", "red_team", "lab", "internal_assessment")


@dataclass
class Policy:
    authorization: str = "bug_bounty"
    # which safety levels are allowed
    passive: bool = True
    safe_active: bool = True
    validation: bool = False
    intrusive: bool = False
    destructive: bool = False           # NEVER defaults on
    # explicitly gated capabilities
    dos: bool = False                   # DoS *resilience assessment* only; no flooding ever
    social_engineering: bool = False    # simulation only, needs opt-in
    # concurrency / timeouts
    workers: int = 8
    timeout: int = 30
    excluded_tools: list[str] = field(default_factory=list)

    # ---- level checks -----------------------------------------------------
    def allows_level(self, level: str) -> bool:
        level = (level or "passive").lower()
        return {
            "passive": self.passive,
            "safe_active": self.safe_active,
            "validation": self.validation,
            "intrusive": self.intrusive,
            "destructive": self.destructive,
        }.get(level, False)

    def max_level(self) -> str:
        allowed = [lvl for lvl in SAFETY_LEVELS if self.allows_level(lvl)]
        return allowed[-1] if allowed else "passive"

    def allows_tool(self, tool: str) -> bool:
        return tool not in self.excluded_tools

    # ---- presets ----------------------------------------------------------
    @classmethod
    def for_profile(cls, profile: str, mode: str = "fast") -> "Policy":
        """
        Map a scan profile+mode to a safe policy. Even 'redteam deep' stays at
        VALIDATION by default — INTRUSIVE/DESTRUCTIVE always require explicit opt-in
        via the policy file / flags, never from the profile alone.
        """
        profile = (profile or "bugbounty").lower()
        deep = mode == "deep"
        p = cls()
        if profile in ("bugbounty", "bug_bounty"):
            p.authorization = "bug_bounty"
            p.validation = deep            # deep bug-bounty may do SAFE validation
        elif profile in ("redteam", "red_team"):
            p.authorization = "red_team"
            p.validation = True            # red team validates, but still not intrusive-by-default
        elif profile == "enterprise":
            p.authorization = "internal_assessment"
            p.validation = deep
        elif profile == "lab":
            p.authorization = "lab"
            p.validation = True
            p.intrusive = deep             # only in a declared LAB may deep enable intrusive
        # web/mobile/cloud/network/etc. behave like a scoped bug-bounty by default
        else:
            p.authorization = "authorized_pentest"
            p.validation = deep
        return p

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        d = d or {}
        testing = d.get("testing", {})
        p = cls(
            authorization=str(d.get("authorization", "bug_bounty")).lower(),
            passive=bool(testing.get("passive", True)),
            safe_active=bool(testing.get("safe_active", True)),
            validation=bool(testing.get("validation", False)),
            intrusive=bool(testing.get("intrusive", False)),
            destructive=bool(testing.get("destructive", False)),
            dos=bool(d.get("dos", {}).get("enabled", False)),
            social_engineering=bool(d.get("social_engineering", {}).get("enabled", False)),
            workers=int(d.get("performance", {}).get("workers", 8)),
            timeout=int(d.get("performance", {}).get("timeout", 30)),
            excluded_tools=list(d.get("tools", {}).get("excluded", [])),
        )
        # HARD SAFETY CLAMP (defense in depth): the most dangerous capabilities
        # can only be enabled in an explicitly authorized context, never by an
        # ambiguous/misparsed config. destructive additionally requires lab.
        if p.authorization not in ("red_team", "lab", "authorized_pentest"):
            p.intrusive = False
        if p.authorization != "lab":
            p.destructive = False
        # a level can only be on if all lower levels are on (no gaps)
        if p.intrusive and not p.validation:
            p.validation = True
        if p.destructive and not p.intrusive:
            p.destructive = False
        return p

    def summary(self) -> str:
        on = [lvl for lvl in SAFETY_LEVELS if self.allows_level(lvl)]
        extra = []
        if self.dos:
            extra.append("dos-resilience")
        if self.social_engineering:
            extra.append("se-simulation")
        return (f"auth={self.authorization} levels={'+'.join(on)}"
                + (f" extras={'+'.join(extra)}" if extra else ""))


def redact(text: str, secrets: list[str]) -> str:
    """Remove operator-supplied secrets from any text before it hits a report/log."""
    out = text or ""
    for s in secrets:
        if s:
            out = out.replace(s, "«redacted»")
    return out
