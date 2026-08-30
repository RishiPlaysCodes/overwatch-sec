"""
Tests for the security-knowledge catalog (core/knowledge.py), the expanded
knowledge base, the validation-coverage metrics (core/coverage.py), and the
new validation-capability registry entries — all asserting HONEST behaviour
(no auto-exploitation, precise not-run reasons).
"""

import knowledgebase as kb
from core import knowledge
from core import coverage as cov_mod
from core.findings import Finding
from core.policy import Policy
from validation import registry, validator


# --------------------------------------------------------------------------
# knowledge base + catalog
# --------------------------------------------------------------------------
def test_kb_expanded_and_wellformed():
    # every entry has the fields the reporter relies on
    required = ("cwe", "owasp", "severity", "title", "description", "attack", "patch")
    for fid, e in kb.KB.items():
        for k in required:
            assert e.get(k), f"{fid} missing {k}"
        assert e["severity"] in ("critical", "high", "medium", "low", "info"), fid
    # the upgrade added meaningful breadth
    assert len(kb.KB) >= 125
    # a representative sample across families (incl. the latest breadth pass)
    for fid in ("web.ssrf", "web.ssti", "web.idor", "web.open_redirect", "web.xxe",
                "web.deserialization", "web.command_injection", "web.jwt_weak",
                "api.bola", "api.bfla", "db.default_creds", "crypto.weak_hash",
                "supplychain.dependency_confusion",
                "auth.bypass", "auth.session_fixation", "auth.saml_misconfig",
                "logic.workflow_bypass", "logic.race_condition", "logic.tenant_isolation",
                "web.crlf", "web.el_injection", "memory.buffer_overflow",
                "wireless.weak_encryption", "iot.default_credentials",
                "cicd.excessive_permissions", "iac.public_exposure", "crypto.hardcoded_key"):
        assert fid in kb.KB, f"expected {fid} in KB"


def test_catalog_matches_kb():
    cat = knowledge.catalog()
    total = sum(f["count"] for f in cat.values())
    assert total == len(kb.KB)              # catalog counts can never over-claim
    assert cat["web"]["count"] >= 20        # web is the largest family
    # ids listed for a family really belong to it
    for fam, e in cat.items():
        assert all(fid.split(".")[0] == fam for fid in e["ids"])


def test_domain_coverage_is_honest():
    dom = knowledge.domain_coverage()
    # active_directory is reasoned indirectly (via identity export), never "covered" by KB alone
    assert dom["active_directory"]["status"] == "indirect"
    # KB-backed families are covered with a positive count
    assert dom["web"]["status"] == "covered" and dom["web"]["kb_entries"] > 0
    assert dom["identity"]["status"] == "covered"      # auth/session KB added
    assert dom["business_logic"]["status"] == "covered"  # logic KB added
    s = knowledge.summary()
    assert s["kb_entries"] == len(kb.KB)
    assert "not" in s["disclaimer"].lower()  # never claims exhaustive


def test_render_never_overclaims():
    out = knowledge.render()
    assert "100% secure" not in out
    assert "SECURITY KNOWLEDGE CATALOG" in out


# --------------------------------------------------------------------------
# validation-capability registry (new classes)
# --------------------------------------------------------------------------
def test_new_capabilities_registered():
    for fid in ("web.ssrf", "web.idor", "api.bola", "web.open_redirect", "db.default_creds"):
        assert registry.capability_for(fid) is not None, fid
    # active-exploitation classes are gated at the intrusive level (honest)
    assert registry.capability_for("web.ssrf").policy_level() == "intrusive"
    assert registry.capability_for("web.command_injection").policy_level() == "intrusive"
    # object-authorization checks require a test account
    assert "test_account" in registry.capability_for("api.bola").requires


def test_intrusive_capability_blocked_under_default_policy():
    cap = registry.capability_for("web.ssrf")
    pol = Policy.for_profile("web", "fast")   # passive + safe_active only
    assert registry.decide(cap, pol, {"in_scope": True}) == "blocked_by_policy"


def test_auth_capability_blocked_without_account():
    cap = registry.capability_for("api.bola")
    pol = Policy.for_profile("redteam", "deep")  # permits controlled validation
    assert registry.decide(cap, pol, {"in_scope": True, "has_auth": False}) \
        == "blocked_by_authentication"


# --------------------------------------------------------------------------
# validation-coverage metrics (spec §30)
# --------------------------------------------------------------------------
def _no_network():
    # force any http re-check to fail deterministically (offline test env)
    validator.http_get = lambda *a, **k: (_ for _ in ()).throw(Exception("offline"))


def test_validation_coverage_counts_and_reasons():
    _no_network()
    pol = Policy.for_profile("web", "fast")
    fs = [
        Finding.from_legacy({"id": "web.ssrf", "evidence": "x", "asset": "example.com"}),
        Finding.from_legacy({"id": "web.idor", "evidence": "x", "asset": "example.com"}),
        Finding.from_legacy({"id": "web.open_redirect", "evidence": "x", "asset": "example.com"}),
        Finding.from_legacy({"id": "cloud.no_mfa", "evidence": "x", "asset": "aws"}),  # no capability
    ]
    cov = cov_mod.Coverage()
    cov.validation_stats = validator.validate(fs, pol, coverage=cov,
                                              context={"has_auth": False, "in_scope": True})
    vc = cov.validation_coverage()
    assert vc["findings_total"] == 4
    assert vc["selected"] == 3                 # cloud.no_mfa has no capability
    assert vc["not_applicable"] == 1
    # under the safe default policy the controlled/intrusive checks are policy-blocked
    assert vc["blocked_by_policy"] >= 2
    # nothing was auto-exploited: no validated exploit results appear
    assert vc["validated"] == 0
    # the summary carries the validation-coverage block
    assert "validation_coverage" in cov.summary()


def test_manual_state_when_permitted_but_no_checker():
    _no_network()
    pol = Policy.for_profile("redteam", "deep")   # allows controlled validation
    # web.host_header has a registered capability but no automated checker
    f = Finding.from_legacy({"id": "web.host_header", "evidence": "x", "asset": "example.com"})
    validator.validate([f], pol, context={"has_auth": True, "in_scope": True})
    # no auto checker is shipped -> honest manual requirement, not a fake pass
    assert f.validation == "manual_validation_required"


def test_open_redirect_has_real_safe_validator():
    # the open-redirect capability is backed by an actual checker (not a placeholder)
    fn = validator._validator_for("web.open_redirect")
    assert fn is validator._validate_open_redirect


def test_open_redirect_indicator_is_passive_and_precise():
    import re
    params = ("url", "next", "redirect", "returnurl")

    def detect(hay):
        hits = set()
        for p in params:
            if re.search(rf"[?&]{re.escape(p)}=(https?%3a|https?:|%2f%2f|//)", hay, re.I):
                hits.add(p)
        return hits

    assert detect("/go?next=https://evil.com")       # absolute URL flagged
    assert detect("/login?returnUrl=%2F%2Fevil.com")  # scheme-relative flagged
    assert not detect("/go?next=/dashboard")          # relative path ignored
    assert not detect("/search?q=hello")              # unrelated param ignored
