"""End-to-end: run the engine against a local insecure server (no external tools)."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core import orchestrator
from reporting import report as report_mod
from reporting import compare as cmp_mod


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "s=1; Path=/")      # missing Secure/HttpOnly/SameSite
        self.send_header("Server", "Apache/2.4.18")         # info leak, no security headers
        self.end_headers()
        self.wfile.write(b"<form action=/u method=post enctype=multipart/form-data>"
                         b"<input type=file name=f></form>")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_full_assessment(server, tmp_path):
    a = orchestrator.run(server, profile="web", mode="fast", outdir=str(tmp_path))
    assert a.kind == "web"
    assert a.scanner == "scanner_web"
    assert len(a.findings) > 0
    # every finding carries epistemics + mitre annotation happened
    assert all(f.confidence for f in a.findings)
    assert a.coverage.attack_techniques >= 1
    # missing security headers should be detected
    ids = {f.id for f in a.findings}
    assert any(i.startswith("web.header") for i in ids)


def test_fast_mode_gates_deep_tools(server, tmp_path):
    # in fast mode, validation-level tools like sqlmap must NOT be selected
    plan = orchestrator.build_plan(server, "web", "fast",
                                   __import__("core.policy", fromlist=["Policy"]).Policy.for_profile("web", "fast"))
    assert "sqlmap" not in plan["tools_selected"]


def test_reports_written_all_formats(server, tmp_path):
    a = orchestrator.run(server, profile="web", mode="fast", outdir=str(tmp_path))
    paths = report_mod.write_all(a, str(tmp_path), formats=("md", "json", "csv", "html"))
    for fmt in ("md", "json", "csv", "html"):
        assert os.path.getsize(paths[fmt]) > 0
    data = json.load(open(paths["json"]))
    assert "summary" in data and "security_score" in data["summary"]


def test_scope_drops_out_of_scope(server, tmp_path):
    from core.scope import Scope
    # scope that allows nothing on 127.0.0.1 -> everything dropped
    a = orchestrator.run(server, profile="web", mode="fast", outdir=str(tmp_path),
                         scope=Scope(allowed=["only-this-domain.example"]))
    assert len(a.findings) == 0
    assert len(a.out_of_scope_dropped) > 0


def test_baseline_compare_self_is_all_persistent(server, tmp_path):
    a = orchestrator.run(server, profile="web", mode="fast", outdir=str(tmp_path))
    jpath = report_mod.write_json(a, str(tmp_path / "report.json"))
    diff = cmp_mod.compare(jpath, a)
    assert diff["counts"]["new"] == 0
    assert diff["counts"]["fixed"] == 0
    assert diff["counts"]["persistent"] == len(a.findings)
