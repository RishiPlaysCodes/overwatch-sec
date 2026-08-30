#!/usr/bin/env python3
"""
tests/run_tests.py — zero-dependency test runner.

Runs the unit tests without needing pytest (handy in minimal/offline
environments). In a normal dev setup just use `pytest`; this runner executes
the same test functions and adds an in-process integration check.

    python3 tests/run_tests.py
"""
import os
import sys
import threading
import tempfile
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import test_scope
import test_policy
import test_detector_findings
import test_attack_paths
import test_phase2
import test_phase3
import test_phase4
import test_phase_pt
import test_phase_res
import test_phase_final
import test_program
import test_knowledge
import test_analyzers
import test_oast

UNIT_MODULES = [test_scope, test_policy, test_detector_findings, test_attack_paths,
                test_phase2, test_phase3, test_phase4, test_phase_pt, test_phase_res,
                test_phase_final, test_program, test_knowledge, test_analyzers, test_oast]


def _run_zero_arg_tests(mod):
    results = []
    for name in dir(mod):
        if not name.startswith("test_"):
            continue
        fn = getattr(mod, name)
        if not callable(fn):
            continue
        # only functions with no required params (skip fixture-based)
        import inspect
        params = [p for p in inspect.signature(fn).parameters.values()
                  if p.default is inspect._empty and p.kind in (p.POSITIONAL_OR_KEYWORD, p.POSITIONAL_ONLY)]
        if params:
            continue
        try:
            fn()
            results.append((f"{mod.__name__}.{name}", True, ""))
        except Exception as e:
            results.append((f"{mod.__name__}.{name}", False, f"{e}\n{traceback.format_exc()}"))
    return results


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "s=1; Path=/")
        self.send_header("Server", "Apache/2.4.18")
        self.end_headers()
        self.wfile.write(b"<form action=/u method=post enctype=multipart/form-data><input type=file name=f></form>")

    def log_message(self, *a):
        pass


def _integration():
    from core import orchestrator
    from core.scope import Scope
    from reporting import report as report_mod
    from reporting import compare as cmp_mod
    srv = HTTPServer(("127.0.0.1", 0), _H)
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    out = []
    try:
        d = tempfile.mkdtemp()
        a = orchestrator.run(url, profile="web", mode="fast", outdir=d)
        out.append(("integration.detects_web", a.kind == "web", f"kind={a.kind}"))
        out.append(("integration.has_findings", len(a.findings) > 0, f"n={len(a.findings)}"))
        out.append(("integration.header_findings",
                    any(f.id.startswith("web.header") for f in a.findings), ""))
        out.append(("integration.mitre_mapped", a.coverage.attack_techniques >= 1, ""))
        paths = report_mod.write_all(a, d, formats=("md", "json", "csv", "html"))
        out.append(("integration.reports_written",
                    all(os.path.getsize(p) > 0 for p in paths.values()), ""))
        # scope drops everything if allow-list excludes the host
        a2 = orchestrator.run(url, profile="web", mode="fast", outdir=d,
                              scope=Scope(allowed=["only.example"]))
        out.append(("integration.scope_drops", len(a2.findings) == 0 and len(a2.out_of_scope_dropped) > 0, ""))
        diff = cmp_mod.compare(paths["json"], a)
        out.append(("integration.compare_self_persistent", diff["counts"]["new"] == 0, ""))
    finally:
        srv.shutdown()
    out += _lab_pipeline()
    return out


def _lab_pipeline():
    """
    End-to-end against the SHIPPED vulnerable lab (lab/app.py):
    detection -> validation -> evidence -> correlation -> report -> redaction.
    """
    import importlib.util
    from core import orchestrator
    from core.policy import Policy
    from core import knowledge
    from reporting import report as report_mod

    spec = importlib.util.spec_from_file_location("lab_app", os.path.join(ROOT, "lab", "app.py"))
    labmod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(labmod)

    srv = HTTPServer(("127.0.0.1", 0), labmod.Handler)
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    out = []
    try:
        d = tempfile.mkdtemp()
        pol = Policy.for_profile("redteam", "deep")  # permits controlled validation
        a = orchestrator.run(url, profile="web", mode="deep", policy=pol,
                             outdir=d, secrets=["deadbeef"])
        ids = {f.id for f in a.findings}
        out.append(("lab.detects_headers", any(i.startswith("web.header") for i in ids), str(ids)))
        out.append(("lab.detects_cookie", "web.cookie.flags" in ids, ""))
        out.append(("lab.detects_open_redirect", "web.open_redirect" in ids, ""))
        validated = [f for f in a.findings if f.validation == "validated"]
        out.append(("lab.has_validated_finding", len(validated) > 0, ""))
        out.append(("lab.validated_has_evidence",
                    bool(validated and validated[0].validation_evidence.get("tool")
                         and validated[0].validation_evidence.get("timestamp")), ""))
        or_f = next((f for f in a.findings if f.id == "web.open_redirect"), None)
        out.append(("lab.open_redirect_validated",
                    or_f is not None and or_f.validation == "validated",
                    (or_f.validation if or_f else "missing")))
        vc = a.coverage.validation_coverage()
        out.append(("lab.validation_coverage", vc["selected"] >= 1 and vc["validated"] >= 1, str(vc)))
        dom = knowledge.coverage_by_domain(a.findings)
        out.append(("lab.domain_coverage_web", dom["web"]["validated"] >= 1, ""))
        md = report_mod.write_markdown(a, os.path.join(d, "report.md"))
        text = open(md).read()
        out.append(("lab.report_coverage_by_domain", "Coverage by domain" in text, ""))
        out.append(("lab.report_validated_section", "Validated findings" in text, ""))
        # the only mention of "100% secure" must be the disclaimer that it is NOT claimed
        low = text.lower()
        out.append(("lab.no_overclaim", "not a claim of" in low and "100% secure" in low, ""))
        # operator secret must be redacted everywhere
        secret_leak = any("deadbeef" in (f.evidence or "") for f in a.findings) or ("deadbeef" in text)
        out.append(("lab.secret_redacted", not secret_leak, ""))
    finally:
        srv.shutdown()
    return out


def main():
    all_results = []
    for m in UNIT_MODULES:
        all_results += _run_zero_arg_tests(m)
    # silence scanner stdout during integration
    import contextlib, io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        all_results += _integration()

    passed = sum(1 for _, ok, _ in all_results if ok)
    failed = [(n, msg) for n, ok, msg in all_results if not ok]
    for name, ok, _ in all_results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{passed}/{len(all_results)} passed")
    if failed:
        print("\nFAILURES:")
        for n, msg in failed:
            print(f"--- {n} ---\n{msg}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
