"""Phase 4 tests: SARIF + gating, connectors, interactive graph, validators."""
import json
import tempfile

from core.findings import Finding
from core.policy import Policy


class _Assessment:
    def __init__(self, findings):
        self.findings = findings
        self.target = "example.com"; self.kind = "web"
        self.profile = "web"; self.mode = "fast"
        self.attack_paths = []; self.coverage = None
        self.scope = _S(); self.policy = _P()


class _S:
    def describe(self): return "example.com"


class _P:
    def summary(self): return "auth=bug_bounty levels=passive+safe_active"
    intrusive = False; destructive = False


def _mk():
    return [Finding(id="web.sqli", title="SQLi", severity="high", asset="example.com", cvss=8.1),
            Finding(id="web.header.csp", title="Missing CSP", severity="medium", asset="example.com")]


def test_sarif_structure():
    from reporting import sarif
    doc = sarif.to_sarif(_Assessment(_mk()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "vulnscan"
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] in ("error", "warning", "note")
    assert "security-severity" in run["tool"]["driver"]["rules"][0]["properties"]


def test_gate_fails_on_severity():
    from reporting import sarif
    code, reason = sarif.gate(_Assessment(_mk()), fail_on="high")
    assert code == 1 and "high" in reason
    code2, _ = sarif.gate(_Assessment(_mk()), fail_on="critical")
    assert code2 == 0  # no critical present


def test_gate_kev():
    from reporting import sarif
    f = Finding(id="web.cve", title="CVE", severity="high", asset="x", kev=True)
    code, reason = sarif.gate(_Assessment([f]), fail_on_kev=True)
    assert code == 1 and "KEV" in reason


def test_gate_ignores_muted():
    from reporting import sarif
    f = _mk()[0]; f.status = "false_positive"
    code, _ = sarif.gate(_Assessment([f]), fail_on="high")
    assert code == 0   # muted finding doesn't trip the gate


def test_connector_bloodhound():
    from connectors import detect_and_load
    bh = {"meta": {"type": "groups"},
          "data": [{"Properties": {"name": "DOMAIN ADMINS", "highvalue": True},
                    "Aces": [{"PrincipalSID": "alice", "RightName": "AddMember"}]}]}
    p = tempfile.mktemp(suffix=".json"); json.dump(bh, open(p, "w"))
    kind, data = detect_and_load(p)
    assert kind == "identity"
    assert any(e["src"] == "alice" for e in data["edges"])


def test_connector_prowler():
    from connectors import detect_and_load
    pw = [{"status": "FAIL", "check_id": "iam_root_mfa", "severity": "high", "check_title": "Root MFA off"},
          {"status": "PASS", "check_id": "ok"}]
    p = tempfile.mktemp(suffix=".json"); json.dump(pw, open(p, "w"))
    kind, data = detect_and_load(p)
    assert kind == "findings"
    assert len(data) == 1 and data[0].severity == "high"


def test_connector_scoutsuite():
    from connectors import detect_and_load
    ss = {"account_id": "1", "services": {"iam": {"users": {"u": {
        "name": "svc", "is_admin": True, "mfa_active": False,
        "access_keys": {"k": {"id": "AKIA", "age_days": 500, "last_used": None}}}}}}}
    p = tempfile.mktemp(suffix=".json"); json.dump(ss, open(p, "w"))
    kind, data = detect_and_load(p)
    assert kind == "threat"
    assert len(data["access_keys"]) == 1


def test_graph_html_interactive():
    from reporting import graph_html
    a = _Assessment(_mk())
    p = tempfile.mktemp(suffix=".html")
    graph_html.write_graph_html(a, p)
    html = open(p).read()
    assert "cytoscape" in html
    assert '"nodes"' in html and '"edges"' in html
    assert "getElementById('sev')" in html   # severity filter present


def test_cors_validator_registered():
    from validation import validator
    assert validator._validator_for("api.cors") is not None
    assert validator._validator_for("web.cookie.flags") is not None
