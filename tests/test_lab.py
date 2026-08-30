"""
tests/test_lab.py — end-to-end pipeline test against the SHIPPED vulnerable lab
(lab/app.py). Verifies the full chain the platform claims:

    detection -> validation -> evidence -> normalization -> correlation -> report

plus per-domain coverage and operator-secret redaction. Uses only the in-process
lab server (no external tools, no real targets).
"""
import importlib.util
import os
import threading
from http.server import HTTPServer

from core import orchestrator
from core.policy import Policy
from reporting import report as report_mod

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_lab_handler():
    spec = importlib.util.spec_from_file_location("lab_app", os.path.join(ROOT, "lab", "app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Handler


def _serve():
    srv = HTTPServer(("127.0.0.1", 0), _load_lab_handler())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _run_deep(outdir, secrets=None):
    """Deep web scan with a validating policy so controlled validation actually runs."""
    srv, url = _serve()
    try:
        pol = Policy.for_profile("redteam", "deep")   # permits controlled validation
        a = orchestrator.run(url, profile="web", mode="deep", policy=pol,
                             outdir=outdir, secrets=secrets or [])
    finally:
        srv.shutdown()
    return a


def test_lab_detection_to_validation_to_evidence(tmp_path):
    a = _run_deep(str(tmp_path))
    ids = {f.id for f in a.findings}
    # DETECTION: the lab's planted issues are found
    assert any(i.startswith("web.header") for i in ids)       # missing security headers
    assert "web.cookie.flags" in ids                          # weak cookie
    assert "web.open_redirect" in ids                         # redirect indicator on the page
    assert "web.infoleak" in ids                              # Server/X-Powered-By banner

    # VALIDATION + EVIDENCE: at least one finding is safely validated with structured,
    # timestamped evidence (tool + timestamp recorded) — not just "detected"
    validated = [f for f in a.findings if f.validation == "validated"]
    assert validated, "expected at least one validated finding against the lab"
    ve = validated[0].validation_evidence
    assert ve.get("tool") and ve.get("timestamp")

    # the open redirect should be VALIDATED end-to-end (safe Location check, not followed)
    or_f = next((f for f in a.findings if f.id == "web.open_redirect"), None)
    assert or_f is not None and or_f.validation == "validated"

    # CORRELATION: MITRE techniques were mapped
    assert a.coverage.attack_techniques >= 1


def test_lab_validation_coverage_metrics(tmp_path):
    a = _run_deep(str(tmp_path))
    vc = a.coverage.validation_coverage()
    assert vc["selected"] >= 1
    assert vc["validated"] >= 1
    # per-domain matrix reflects validated web findings
    from core import knowledge
    dom = knowledge.coverage_by_domain(a.findings)
    assert dom["web"]["findings"] >= 1
    assert dom["web"]["validated"] >= 1


def test_lab_report_contains_coverage_and_validation_sections(tmp_path):
    a = _run_deep(str(tmp_path))
    md = report_mod.write_markdown(a, str(tmp_path / "report.md"))
    text = open(md).read()
    assert "Coverage by domain" in text
    assert "Validation status" in text
    assert "Validated findings" in text
    low = text.lower()
    assert "not a claim of" in low and "100% secure" in low   # disclaimed, never claimed


def test_lab_secret_redaction(tmp_path):
    # supply the lab's session cookie value as an operator secret; it must never
    # appear in findings evidence or the written report
    a = _run_deep(str(tmp_path), secrets=["deadbeef"])
    for f in a.findings:
        assert "deadbeef" not in (f.evidence or "")
    md = report_mod.write_markdown(a, str(tmp_path / "report.md"))
    assert "deadbeef" not in open(md).read()
