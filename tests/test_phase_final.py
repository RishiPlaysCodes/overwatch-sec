"""Final-phase tests: linux/windows scanners, social engineering, finding fields."""
import json
import tempfile

from core.findings import Finding


def _write(obj):
    p = tempfile.mktemp(suffix=".json")
    with open(p, "w") as fh:
        json.dump(obj, fh)
    return p


def test_finding_has_capec_root_cause():
    f = Finding(id="x", title="t")
    assert f.capec == [] and f.root_cause == ""
    d = f.to_dict()
    assert "capec" in d and "root_cause" in d


def test_linux_scanner():
    import scanner_linux
    p = _write({"suid": ["/usr/bin/find", "/tmp/x"], "sudo": ["(ALL) NOPASSWD: /usr/bin/vim"],
                "sshd_config": {"PermitRootLogin": "yes"}, "capabilities": ["/usr/bin/python = cap_setuid+ep"]})
    r = scanner_linux.scan(p, tempfile.mkdtemp(), set())
    ids = {f["id"] for f in r["findings"]}
    assert {"linux.suid", "linux.sudo", "linux.ssh_config", "linux.capabilities"} <= ids


def test_windows_scanner():
    import scanner_windows
    p = _write({"services": [{"name": "S", "path": "C:\\Program Files\\a b\\s.exe", "writable_dir": True}],
                "exposed": {"smb": True, "smbv1": True, "signing": False, "rdp": True, "nla": False}})
    r = scanner_windows.scan(p, tempfile.mkdtemp(), set())
    ids = {f["id"] for f in r["findings"]}
    assert "windows.unquoted_service" in ids and "windows.smb_exposed" in ids


def test_target_detection_linux_windows():
    from core.target_detector import detect
    lp = _write({"suid": [], "sshd_config": {}})
    wp = _write({"services": [], "exposed": {"smb": True}})
    assert detect(lp)["kind"] == "linux"
    assert detect(wp)["kind"] == "windows"


def test_social_engineering_analysis():
    from social_engineering import simulation
    r = simulation.analyze({"sent": 100, "clicked": 40, "submitted_dummy_credentials": 12,
                            "reported": 10, "mfa_prompted": 12, "mfa_denied": 4,
                            "policy": {"has_reporting_button": False, "mfa_enforced": False}})
    m = r["metrics"]
    assert m["click_rate"] == 40 and m["reporting_rate"] == 10
    ids = {f.id for f in r["findings"]}
    assert "se.high_click_rate" in ids and "se.credential_submission" in ids
    # never stores real credentials — submission is a rate/count only
    assert isinstance(m["credential_submission_rate"], int)


def test_social_engineering_policy_gate():
    # SE analysis in the orchestrator requires policy.social_engineering enabled
    from core.policy import Policy
    assert Policy().social_engineering is False



def test_report_bundle():
    import os
    from reporting import bundle

    class _S:
        def describe(self): return "example.com"

    class _P:
        def summary(self): return "auth=bug_bounty levels=passive+safe_active"
        intrusive = False; destructive = False

    class _Cov:
        def summary(self): return {"stages_ran": 1, "tools_executed": []}
        def render(self): return "COVERAGE"

    class _A:
        target = "example.com"; kind = "web"; profile = "web"; mode = "fast"; scan_id = "SCAN-X"
        findings = [Finding(id="web.sqli", title="SQLi", severity="high", asset="example.com",
                            validation="validated", cvss=8.1)]
        attack_paths = []; detection = {}; social = {}; out_of_scope_dropped = []
        scope = _S(); policy = _P(); coverage = _Cov()
        def to_dict(self):
            return {"findings": [f.to_dict() for f in self.findings], "attack_paths": [],
                    "coverage": {}, "target": self.target}

    d = tempfile.mkdtemp()
    paths = bundle.write_bundle(_A(), d, pdf=True)
    reports = os.path.join(d, "reports")
    for fn in ("executive-report.md", "technical-report.md", "findings.json",
               "attack-paths.json", "coverage.json", "manifest.json"):
        assert os.path.isfile(os.path.join(reports, fn)), fn
    # per-finding evidence written
    assert os.path.isdir(os.path.join(reports, "evidence"))
    assert len(os.listdir(os.path.join(reports, "evidence"))) == 1
    # exec report has business framing
    exec_txt = open(os.path.join(reports, "executive-report.md")).read()
    assert "Executive Security Report" in exec_txt and "Security score" in exec_txt



def test_loadtest_refuses_without_lab_and_optin():
    from validation import loadtest
    from core.policy import Policy
    # default policy: not lab, dos off, no opt-in -> refuses (empty result)
    assert loadtest.run("http://127.0.0.1:9", Policy(), opt_in=False) == []
    ok, _ = loadtest.allowed(Policy(), True)
    assert ok is False
    ok2, _ = loadtest.allowed(Policy(authorization="lab", dos=True), True)
    assert ok2 is True


def test_loadtest_hard_caps():
    from validation import loadtest
    assert loadtest.MAX_REQUESTS <= 50 and loadtest.MAX_CONCURRENCY <= 5 and loadtest.MAX_SECONDS <= 10


def test_baseline_store_roundtrip():
    import core.checkpoint as ckpt
    import tempfile, os, json
    ckpt.BASELINE_DIR = tempfile.mkdtemp()
    rep = tempfile.mktemp(suffix=".json")
    json.dump({"findings": [], "summary": {"security_score": 90}}, open(rep, "w"))
    assert ckpt.find_baseline("https://x.com") is None
    saved = ckpt.save_baseline("https://x.com", rep)
    assert saved and os.path.isfile(saved)
    assert ckpt.find_baseline("https://x.com") == saved
