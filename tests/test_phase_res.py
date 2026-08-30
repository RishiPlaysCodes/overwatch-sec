"""Checkpoint/resume + availability assessment tests."""
import tempfile

from core.findings import Finding


def test_checkpoint_save_restore(monkeypatch=None):
    import core.checkpoint as ckpt
    d = tempfile.mkdtemp()
    # redirect the cache dir to a temp location
    ckpt.CACHE_DIR = d
    cp = ckpt.Checkpoint("SCAN-TEST-1", {"target": "x.com", "profile": "web", "mode": "fast", "kind": "web"})
    cp.mark("scan", "running")
    fs = [Finding(id="web.sqli", title="SQLi", severity="high", asset="x.com", validation="validated")]
    cp.store_findings(fs)
    cp.mark("collect", "completed")
    # reload
    c2 = ckpt.Checkpoint.load("SCAN-TEST-1")
    assert c2 is not None
    assert c2.is_completed("collect")
    rf = c2.restore_findings()
    assert len(rf) == 1 and rf[0].id == "web.sqli" and rf[0].validation == "validated"


def test_resume_scan_rebuilds(monkeypatch=None):
    import core.checkpoint as ckpt
    from core import orchestrator
    d = tempfile.mkdtemp()
    ckpt.CACHE_DIR = d
    cp = ckpt.Checkpoint("SCAN-TEST-2", {"target": "x.com", "profile": "web", "mode": "fast", "kind": "web"})
    cp.store_findings([Finding(id="web.sqli", title="SQLi", severity="high", asset="x.com",
                               validation="validated", cvss=8.0)])
    cp.mark("collect", "completed")
    a = orchestrator.resume_scan("SCAN-TEST-2")
    assert a is not None
    assert len(a.findings) == 1
    assert a.attack_paths  # re-derived without rescanning


def test_resume_missing_returns_none():
    from core import orchestrator
    assert orchestrator.resume_scan("SCAN-DOES-NOT-EXIST-xyz") is None


def test_availability_assessment_is_passive():
    # unreachable target -> no assertions (never fabricates), no crash
    from validation import resilience
    out = resilience.assess("http://127.0.0.1:9")
    assert isinstance(out, list)
