"""Program-config (bug-bounty) tests."""
import os
import tempfile

from core import program as prog
from core.findings import Finding


def _write(text, ext=".yaml"):
    p = tempfile.mktemp(suffix=ext)
    with open(p, "w") as fh:
        fh.write(text)
    return p


def test_load_yaml_program():
    p = _write("name: T\nscope:\n  - example.com\n  - '*.example.com'\n"
               "headers:\n  X-Request-Purpose: BugcrowdResearch\nrate_per_min: 20\n"
               "exclude_findings:\n  - web.header*\n  - availability*\n"
               "focus_findings:\n  - web.sqli\n")
    pr = prog.load(p)
    assert pr.name == "T"
    assert pr.scope.allows("api.example.com") and not pr.scope.allows("evil.com")
    assert pr.headers.get("X-Request-Purpose") == "BugcrowdResearch"
    assert pr.rate_per_min == 20
    assert pr.is_out_of_scope_finding("web.header.csp")
    assert pr.is_out_of_scope_finding("availability.no_rate_limit")
    assert not pr.is_out_of_scope_finding("web.sqli")
    assert pr.is_focus_finding("web.sqli")
    os.remove(p)


def test_txt_program_uses_default_oos():
    p = _write("example.com\n*.example.com\n", ext=".txt")
    pr = prog.load(p)
    assert pr.scope.allows("x.example.com")
    assert pr.is_out_of_scope_finding("web.header.hsts")  # default OOS applied
    os.remove(p)


def test_apply_headers_and_rate_to_context():
    import common
    p = _write("name: H\nscope:\n  - x.com\nheaders:\n  X-Request-Purpose: BugcrowdResearch\n"
               "rate_per_min: 120\n")
    pr = prog.load(p)
    prog.apply_to_request_context(pr)
    assert common.REQUEST_CONTEXT["headers"].get("X-Request-Purpose") == "BugcrowdResearch"
    assert common.REQUEST_CONTEXT["min_interval"] > 0
    # reset context so other tests are unaffected
    common.REQUEST_CONTEXT["headers"] = {}
    common.REQUEST_CONTEXT["min_interval"] = 0.0
    os.remove(p)


def test_header_cli_args_for_tools():
    import common
    common.set_request_context({"X-Request-Purpose": "BugcrowdResearch"})
    assert common.header_cli_args("httpx") == ["-H", "X-Request-Purpose: BugcrowdResearch"]
    assert common.header_cli_args("sqlmap") == ["--header", "X-Request-Purpose: BugcrowdResearch"]
    common.REQUEST_CONTEXT["headers"] = {}


def test_shipped_matlab_config_valid():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pr = prog.load(os.path.join(root, "programs", "matlab-bugcrowd.yaml"))
    assert pr is not None
    assert pr.scope.allows("matlab.mathworks.com")
    assert pr.headers.get("X-Request-Purpose") == "BugcrowdResearch"
    assert pr.is_out_of_scope_finding("web.header.csp")
    assert pr.is_focus_finding("web.sqli")
