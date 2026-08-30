"""
Tests for the capability matrix (§2/§56) and the controlled OAST SSRF safe-proof
framework (§37/§38). Self-contained (in-process servers); no real targets.
"""
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from core import capability_matrix as cm
from core.findings import Finding
from core.policy import Policy
from validation import oast, validator


# --------------------------------------------------------------------------
# capability matrix
# --------------------------------------------------------------------------
def test_capability_matrix_has_no_unexplained_gaps():
    s = cm.summary()
    assert s["total_capabilities"] > 20
    assert s["unexplained_gaps"] == []          # every capability carries a reason
    # every row uses a status from the exact contract vocabulary
    for r in cm.matrix():
        assert r["status"] in cm.STATUSES, r
        assert r["reason"]


def test_capability_matrix_marks_core_families_implemented():
    by = {r["capability"]: r["status"] for r in cm.matrix()}
    assert by["web"] == "IMPLEMENTED_AND_TESTED"
    assert by["cicd"] == "IMPLEMENTED_AND_TESTED"
    assert by["iac"] == "IMPLEMENTED_AND_TESTED"
    # honest gating of things we cannot safely/automatically do
    assert by["memory"] == "NOT_APPLICABLE"
    assert by["wireless"] == "REQUIRES_SPECIAL_HARDWARE"
    assert by["windows"] == "REQUIRES_TARGET_SPECIFIC_CONFIGURATION"


# --------------------------------------------------------------------------
# OAST SSRF safe proof
# --------------------------------------------------------------------------
def _ssrf_server():
    """A mock server whose /fetch?url=X makes a server-side request to X (SSRF sink)."""
    class Vuln(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            u = parse_qs(urlparse(self.path).query).get("url", [None])[0]
            if u:
                try:
                    urllib.request.urlopen(u, timeout=3).read(16)
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Vuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/fetch"


def test_oast_ssrf_validated_with_collaborator():
    col = oast.LocalCollaborator().start()
    srv, base = _ssrf_server()
    try:
        f = Finding.from_legacy({"id": "web.ssrf", "asset": base, "component": "url",
                                 "evidence": "param url"})
        pol = Policy.for_profile("lab", "deep")   # intrusive enabled only in lab
        validator.validate([f], pol, context={"in_scope": True, "has_auth": True, "collaborator": col})
        assert f.validation == "validated"
        assert "oast" in f.validation_evidence      # out-of-band callback evidence captured
    finally:
        srv.shutdown()
        col.stop()


def test_oast_ssrf_manual_without_collaborator():
    srv, base = _ssrf_server()
    try:
        f = Finding.from_legacy({"id": "web.ssrf", "asset": base, "component": "url", "evidence": "x"})
        pol = Policy.for_profile("lab", "deep")
        validator.validate([f], pol, context={"in_scope": True, "has_auth": True})
        # no collaborator configured -> honest manual, never a fabricated 'validated'
        assert f.validation == "manual_validation_required"
    finally:
        srv.shutdown()


def test_oast_ssrf_blocked_under_safe_policy():
    f = Finding.from_legacy({"id": "web.ssrf", "asset": "http://x/fetch", "component": "url", "evidence": "x"})
    validator.validate([f], Policy.for_profile("web", "fast"), context={"in_scope": True})
    # intrusive not permitted by the default safe policy -> blocked, not run
    assert f.validation == "blocked_by_policy"
