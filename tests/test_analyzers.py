"""
Tests for the dependency-free CI/CD + IaC analyzers, their integration into the
code scanner, and the capability/gap-analysis engine. Uses intentionally-vulnerable
temp fixtures (never real targets). Zero-arg so the bundled runner executes them.
"""
import os
import tempfile

from analyzers import cicd, iac
from core import gap_analysis


def _mkrepo():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, ".github", "workflows"))
    with open(os.path.join(d, ".github", "workflows", "ci.yml"), "w") as fh:
        fh.write(
            "name: ci\n"
            "on: pull_request_target\n"
            "permissions: write-all\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - uses: some-org/thirdparty-action@v1\n"
            "      - run: echo \"title ${{ github.event.pull_request.title }}\"\n"
            "      - run: echo \"${{ secrets.API_TOKEN }}\"\n")
    with open(os.path.join(d, "Dockerfile"), "w") as fh:
        fh.write("FROM ubuntu:latest\n"
                 "RUN curl http://x/i.sh | sh\n"
                 "ENV API_KEY=\"supersecretvalue123\"\n")
    with open(os.path.join(d, "main.tf"), "w") as fh:
        fh.write('resource "aws_security_group" "w" { ingress { cidr_blocks = ["0.0.0.0/0"] } }\n'
                 'resource "aws_s3_bucket" "b" { acl = "public-read" }\n'
                 'resource "db" "d" { password = "hardcodedpass123" }\n')
    with open(os.path.join(d, "deploy.yaml"), "w") as fh:
        fh.write("apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n"
                 "  containers:\n    - name: a\n      securityContext:\n        privileged: true\n"
                 "  volumes:\n    - hostPath: { path: / }\n")
    return d


def test_cicd_detects_github_actions_issues():
    d = _mkrepo()
    ids = {f["id"] for f in cicd.analyze_dir(d)}
    for expected in ("cicd.excessive_permissions", "cicd.pr_target_checkout",
                     "cicd.script_injection", "cicd.untrusted_action", "cicd.secret_exposure"):
        assert expected in ids, f"CI/CD analyzer missed {expected} ({ids})"


def test_cicd_clean_workflow_has_no_findings():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, ".github", "workflows"))
    with open(os.path.join(d, ".github", "workflows", "ok.yml"), "w") as fh:
        fh.write("name: ci\non: push\npermissions:\n  contents: read\njobs:\n"
                 "  b:\n    runs-on: ubuntu-latest\n    steps:\n"
                 "      - uses: actions/checkout@a1b2c3d4e5f6a7b8c9d0112233445566778899aa\n"
                 "      - run: make test\n")
    assert cicd.analyze_dir(d) == []      # no false positives on a hardened workflow


def test_iac_detects_dockerfile_terraform_k8s():
    d = _mkrepo()
    ids = [f["id"] for f in iac.analyze_dir(d)]
    idset = set(ids)
    assert "container.misconfig" in idset       # Dockerfile: latest / curl|sh / no USER
    assert "iac.hardcoded_secret" in idset       # tf + dockerfile secrets
    assert "iac.public_exposure" in idset        # 0.0.0.0/0 + public-read
    assert "k8s.privileged" in idset
    assert "k8s.hostpath" in idset
    assert "k8s.hostnet" in idset


def test_scanner_code_runs_analyzers_end_to_end():
    import scanner_code
    d = _mkrepo()
    out = tempfile.mkdtemp()
    res = scanner_code.scan(d, out, skip=set())
    ids = {f["id"] for f in res["findings"]}
    tools = {t["tool"] for t in res["tools"]}
    assert "cicd-analyzer" in tools and "iac-analyzer" in tools
    assert any(i.startswith("cicd.") for i in ids), ids
    assert any(i in ids for i in ("iac.public_exposure", "k8s.privileged", "container.misconfig"))


def test_gap_analysis_matrix_is_consistent():
    m = gap_analysis.matrix()
    assert m["kb_total"] > 100
    assert m["capabilities_total"] > 0
    assert m["validators_total"] >= 6
    # every built-in validator must have capability metadata (no orphan core checkers);
    # note the engine legitimately reports plugin-registered validators without metadata.
    orphans = set(m["validator_without_capability"])
    for core_vp in ("web.header", "web.xss.reflected", "recon.dir_listing",
                    "api.cors", "web.cookie", "web.open_redirect"):
        assert core_vp not in orphans
    # the new CI/CD ids are statically emitted (analyzer wired to real detection)
    emitted = gap_analysis.emitted_ids()
    assert "cicd.excessive_permissions" in emitted
    assert "iac.public_exposure" in emitted
