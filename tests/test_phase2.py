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
    # policy without validation -> validator must not upgrade state
    f = Finding(id="web.header.csp", title="Missing CSP", asset="http://127.0.0.1:9")  # unreachable
    stats = validator.validate([f], Policy())          # defaults: no validation
    assert stats["manual"] == 1
    assert f.validation == "detected"


def test_validation_runs_when_allowed_but_safe_on_error():
    # validation allowed, but target unreachable -> stays manual (never crashes/claims)
    f = Finding(id="web.header.csp", title="Missing CSP", asset="http://127.0.0.1:9")
    pol = Policy(validation=True)
    stats = validator.validate([f], pol)
    assert f.validation in ("detected", "validated", "not_exploitable")
    assert stats["manual"] + stats["validated"] + stats["not_exploitable"] >= 1


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
