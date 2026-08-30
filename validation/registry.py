#!/usr/bin/env python3
"""
validation/registry.py — machine-readable validation-capability registry.

Every controlled-validation test declares WHAT it needs and how risky it is, so
the engine can decide — per finding, per policy, per context — whether to run it,
and if not, exactly WHY (blocked_by_policy / _authentication / _missing_dependency
/ _scope). This is the "intelligent test selection" layer: we never blindly run
everything; we run the relevant, permitted, safe checks.

A capability is metadata only; the actual check is a callable registered in
validation/validator.py. Plugins can add capabilities via add_capability().
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field

# safety level of a validation test (maps onto core.policy levels;
# 'controlled_validation' == the policy 'validation' level)
SAFE_LEVELS = ("passive", "safe_active", "controlled_validation", "intrusive", "destructive")
_LEVEL_TO_POLICY = {
    "passive": "passive", "safe_active": "safe_active",
    "controlled_validation": "validation", "intrusive": "intrusive", "destructive": "destructive",
}


@dataclass
class ValidationCapability:
    id: str                          # e.g. "web.header.validate"
    applies_to: str                  # finding-id prefix this validates
    name: str = ""
    target_types: tuple = ()         # web/api/network/... (informational)
    requires: tuple = ()             # authorized_target | test_account | http | <toolname>
    risk: str = "controlled_validation"
    destructive: bool = False
    changes_state: bool = False
    affects_availability: bool = False
    profiles: tuple = ()             # empty => all profiles
    evidence: tuple = ("request", "response")
    cleanup: str = "none"
    timeout: int = 15

    def policy_level(self) -> str:
        return _LEVEL_TO_POLICY.get(self.risk, "validation")


# id-prefix -> capability metadata
CAPABILITIES: dict[str, ValidationCapability] = {
    "web.header": ValidationCapability(
        id="web.header.validate", applies_to="web.header", name="Security header re-check",
        target_types=("web", "api"), requires=("authorized_target", "http"),
        risk="safe_active", evidence=("request", "response_headers")),
    "web.cookie": ValidationCapability(
        id="web.cookie.validate", applies_to="web.cookie", name="Cookie flags re-check",
        target_types=("web",), requires=("authorized_target", "http"), risk="safe_active",
        evidence=("response_headers",)),
    "web.xss.reflected": ValidationCapability(
        id="web.xss.reflection.validate", applies_to="web.xss.reflected",
        name="Reflected-input confirmation", target_types=("web",),
        requires=("authorized_target", "http"), risk="controlled_validation",
        evidence=("request", "response")),
    "recon.dir_listing": ValidationCapability(
        id="recon.dirlisting.validate", applies_to="recon.dir_listing",
        name="Directory-listing confirmation", target_types=("web", "recon"),
        requires=("authorized_target", "http"), risk="safe_active"),
    "api.cors": ValidationCapability(
        id="api.cors.validate", applies_to="api.cors", name="CORS reflection confirmation",
        target_types=("api", "web"), requires=("authorized_target", "http"),
        risk="controlled_validation", evidence=("request", "response_headers")),

    # --- classes we can only confirm with a benign, non-destructive re-observation
    #     (no auto-exploit shipped -> resolve to manual_validation_required when the
    #      policy permits controlled validation; blocked_by_policy otherwise) --------
    "web.open_redirect": ValidationCapability(
        id="web.open_redirect.validate", applies_to="web.open_redirect",
        name="Open-redirect confirmation (manual)", target_types=("web",),
        requires=("authorized_target", "http"), risk="controlled_validation"),
    "web.host_header": ValidationCapability(
        id="web.host_header.validate", applies_to="web.host_header",
        name="Host-header handling review (manual)", target_types=("web",),
        requires=("authorized_target", "http"), risk="controlled_validation"),
    "web.jwt_weak": ValidationCapability(
        id="web.jwt_weak.validate", applies_to="web.jwt_weak",
        name="JWT verification review (manual)", target_types=("web", "api"),
        requires=("authorized_target",), risk="controlled_validation"),
    "web.mass_assignment": ValidationCapability(
        id="web.mass_assignment.validate", applies_to="web.mass_assignment",
        name="Mass-assignment review (manual)", target_types=("web", "api"),
        requires=("authorized_target",), risk="controlled_validation"),

    # --- object/function authorization: needs a test account to prove access -------
    "web.idor": ValidationCapability(
        id="web.idor.validate", applies_to="web.idor",
        name="IDOR ownership check (needs test account)", target_types=("web", "api"),
        requires=("authorized_target", "test_account"), risk="controlled_validation"),
    "api.bola": ValidationCapability(
        id="api.bola.validate", applies_to="api.bola",
        name="BOLA authorization check (needs test account)", target_types=("api",),
        requires=("authorized_target", "test_account"), risk="controlled_validation"),
    "api.bfla": ValidationCapability(
        id="api.bfla.validate", applies_to="api.bfla",
        name="BFLA authorization check (needs test account)", target_types=("api",),
        requires=("authorized_target", "test_account"), risk="controlled_validation"),

    # --- active-exploitation classes: real validation requires intrusive testing,
    #     so under the default safe policy these are honestly blocked_by_policy
    #     (we do NOT ship auto-exploitation) --------------------------------------
    "web.ssrf": ValidationCapability(
        id="web.ssrf.validate", applies_to="web.ssrf", name="SSRF confirmation (intrusive)",
        target_types=("web", "api"), requires=("authorized_target", "http"),
        risk="intrusive", changes_state=True),
    "web.ssti": ValidationCapability(
        id="web.ssti.validate", applies_to="web.ssti", name="SSTI confirmation (intrusive)",
        target_types=("web",), requires=("authorized_target", "http"), risk="intrusive"),
    "web.command_injection": ValidationCapability(
        id="web.cmdi.validate", applies_to="web.command_injection",
        name="Command-injection confirmation (intrusive)", target_types=("web",),
        requires=("authorized_target", "http"), risk="intrusive", changes_state=True),
    "web.deserialization": ValidationCapability(
        id="web.deser.validate", applies_to="web.deserialization",
        name="Deserialization confirmation (intrusive)", target_types=("web", "api"),
        requires=("authorized_target", "http"), risk="intrusive", changes_state=True),
    "web.xxe": ValidationCapability(
        id="web.xxe.validate", applies_to="web.xxe", name="XXE confirmation (intrusive)",
        target_types=("web", "api"), requires=("authorized_target", "http"), risk="intrusive"),
    "web.path_traversal": ValidationCapability(
        id="web.pathtrav.validate", applies_to="web.path_traversal",
        name="Path-traversal confirmation (intrusive)", target_types=("web",),
        requires=("authorized_target", "http"), risk="intrusive"),
    "db.default_creds": ValidationCapability(
        id="db.default_creds.validate", applies_to="db.default_creds",
        name="Default-credential check (intrusive)", target_types=("network", "database"),
        requires=("authorized_target",), risk="intrusive"),
}


def add_capability(cap: ValidationCapability) -> None:
    CAPABILITIES[cap.applies_to] = cap


def capability_for(finding_id: str) -> ValidationCapability | None:
    if finding_id in CAPABILITIES:
        return CAPABILITIES[finding_id]
    best = None
    for prefix, cap in CAPABILITIES.items():
        if finding_id.startswith(prefix):
            if best is None or len(prefix) > len(best.applies_to):
                best = cap
    return best


def decide(cap: ValidationCapability, policy, context: dict) -> str:
    """
    Decide whether this capability may run now. Returns:
      "run" | "blocked_by_policy" | "blocked_by_authentication"
      | "blocked_by_missing_dependency" | "blocked_by_scope"
    """
    context = context or {}
    # scope (network-facing only; orchestrator sets in_scope)
    if context.get("in_scope") is False:
        return "blocked_by_scope"
    # policy safety level
    if not policy.allows_level(cap.policy_level()):
        return "blocked_by_policy"
    # destructive/state-changing extra gate
    if cap.destructive and not policy.allows_level("destructive"):
        return "blocked_by_policy"
    # authentication prerequisite
    if "test_account" in cap.requires and not context.get("has_auth"):
        return "blocked_by_authentication"
    # tool prerequisites
    for req in cap.requires:
        if req in ("authorized_target", "http", "test_account"):
            continue
        # treat any other requirement as an external tool that must be installed
        if not shutil.which(req):
            return "blocked_by_missing_dependency"
    return "run"


def summary() -> list[dict]:
    return [{"id": c.id, "applies_to": c.applies_to, "risk": c.risk,
             "requires": list(c.requires), "destructive": c.destructive,
             "profiles": list(c.profiles) or ["all"]} for c in CAPABILITIES.values()]
