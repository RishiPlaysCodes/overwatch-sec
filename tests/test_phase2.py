"""Phase 2 tests: graph engine, validation gating, triage persistence, plugins."""
import os
import tempfile

from core.findings import Finding
from core.policy import Policy
from attack_paths import mitre, graph
from validation import validator
from core.triage import TriageStore
from core import plugins


def _findings():
    fs = [
        Finding(id="code.secret", title="AWS key", severity="high", asset="app.x.com", cvss=7.5),
        Finding(id="web.sqli", title="SQLi", severity="high", asset="api.x.com", kev=True, cvss=9.1),
        Finding(id="cloud.iam_wildcard", title="Wildcard IAM", severity="critical", asset="aws-acct"),
    ]
    mitre.annotate(fs)
    return fs


def test_graph_builds_objectives_and_lateral():
    fs = _findings()
    g = graph.build(fs, "x.com")
    kinds = {n.kind for n in g.nodes.values()}
    assert {"entry", "asset", "finding", "objective"} <= kinds
    # a credential objective should create a lateral edge to another asset
    assert any(rel == "lateral" for _, _, rel in g.edges)


def test_graph_paths_reach_objectives_with_risk():
    fs = _findings()
    paths = graph.build_paths(fs, "x.com")
    assert paths
    assert any(p.get("objective") for p in paths)
    assert any(p.get("multi_asset") for p in paths)
    assert paths[0]["risk_score"] > 0


def test_mermaid_export():
    mm = graph.to_mermaid(_findings(), "x.com")
    assert mm.startswith("flowchart")
    assert "-->" in mm


def test_validation_gated_by_policy():
    # a controlled_validation capability (reflected XSS) is blocked under the
    # default policy (passive + safe_active only) -> precise blocked_by_policy state
    f = Finding(id="web.xss.reflected", title="Reflected input", asset="http://127.0.0.1:9")
    stats = validator.validate([f], Policy())
    assert f.validation == "blocked_by_policy"
    assert stats["blocked_by_policy"] == 1
    assert f.validation_evidence.get("reason")


def test_validation_runs_when_allowed_but_safe_on_error():
    # validation allowed, target unreachable -> records error/not_validated,
    # never crashes and never falsely claims success
    f = Finding(id="web.xss.reflected", title="Reflected input", asset="http://127.0.0.1:9")
    validator.validate([f], Policy(validation=True))
    assert f.validation in ("error", "not_validated", "validated", "manual_validation_required")
    assert f.validation != "detected"


def test_triage_persists_and_applies():
    path = tempfile.mktemp(suffix=".json")
    f = Finding(id="web.header.csp", title="Missing CSP", asset="x.com")
    s = TriageStore.load(path)
    s.mark(f.fingerprint(), "false_positive", note="mitigated")
    s.save()
    s2 = TriageStore.load(path)
    assert s2.apply([f]) == 1
    assert f.status == "false_positive"
    assert s2.active_findings([f]) == []
    os.remove(path)


def test_triage_rejects_bad_status():
    s = TriageStore()
    try:
        s.mark("abc", "not_a_status")
        assert False, "should have raised"
    except ValueError:
        pass


def test_plugin_loading_registers_extensions():
    loaded = plugins.load_plugins()
    assert any("graphql" in p for p in loaded)
    assert mitre.technique_for("web.graphql") is not None
    assert graph._objective_for("web.graphql") is not None



def test_capability_registry_and_decisions():
    from validation import registry
    from core.policy import Policy
    cap = registry.capability_for("web.xss.reflected")
    assert cap is not None and cap.policy_level() == "validation"
    # safe_active header re-check runs under default policy
    hdr = registry.capability_for("web.header.csp")
    assert registry.decide(hdr, Policy(), {}) == "run"
    # controlled_validation blocked by default
    assert registry.decide(cap, Policy(), {}) == "blocked_by_policy"
    # out-of-scope always blocked
    assert registry.decide(hdr, Policy(), {"in_scope": False}) == "blocked_by_scope"


def test_capability_missing_dependency_and_auth():
    from validation import registry
    from core.policy import Policy
    c = registry.ValidationCapability(id="x.validate", applies_to="x",
                                      requires=("authorized_target", "definitely-not-installed-tool"),
                                      risk="controlled_validation")
    assert registry.decide(c, Policy(validation=True), {}) == "blocked_by_missing_dependency"
    c2 = registry.ValidationCapability(id="y.validate", applies_to="y",
                                       requires=("authorized_target", "test_account"),
                                       risk="controlled_validation")
    assert registry.decide(c2, Policy(validation=True), {"has_auth": False}) == "blocked_by_authentication"
    assert registry.decide(c2, Policy(validation=True), {"has_auth": True}) == "run"



def test_attack_path_step_confidence():
    from core.findings import Finding
    from attack_paths import graph, mitre
    fs = [Finding(id="web.sqli", title="SQLi", severity="high", asset="a.x", validation="validated"),
          Finding(id="code.secret", title="Secret", severity="high", asset="a.x", validation="detected")]
    mitre.annotate(fs)
    assert graph.step_confidence("validated") == "CONFIRMED"
    assert graph.step_confidence("detected") == "ASSUMED"
    assert graph.step_confidence("blocked_by_policy") == "UNVALIDATED"
    paths = graph.build_paths(fs, "x")
    assert paths
    p = paths[0]
    assert p["path_confidence"] in ("CONFIRMED", "PARTIAL", "ASSUMED")
    assert all("confidence" in s for s in p["steps"])
    assert "confirmed_steps" in p and "unvalidated_assumptions" in p
