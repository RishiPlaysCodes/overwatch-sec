#!/usr/bin/env python3
"""
analyzers/cicd.py — dependency-free CI/CD pipeline security analyzer.

Statically analyzes common CI/CD definitions found in a repository and emits
normalized findings (via common.finding). No external tools, no network.

Supported formats:
  - GitHub Actions   (.github/workflows/*.yml|*.yaml)
  - GitLab CI        (.gitlab-ci.yml)
  - Jenkins          (Jenkinsfile)
  - generic pipeline YAML (best-effort pattern checks)

Detections (real config facts — DETECTED state):
  - excessive workflow permissions (write-all / write)              -> cicd.excessive_permissions
  - pull_request_target + checkout of untrusted PR code             -> cicd.pr_target_checkout
  - untrusted input interpolated into a run script (${{ github.event.* }}) -> cicd.script_injection
  - third-party action not pinned to a commit SHA                   -> cicd.untrusted_action
  - secret echoed / exposed in a shell step                          -> cicd.secret_exposure

These are pattern-based static findings; exploitability depends on repo settings
(e.g. who can open PRs) and remains for review — never auto-marked exploited.
"""

from __future__ import annotations

import os
import re

try:
    from common import finding
except Exception:  # pragma: no cover - fallback when imported oddly
    def finding(fid, evidence, severity_override=None):
        return {"id": fid, "evidence": evidence, "severity": severity_override or "info"}

_SHA_RE = re.compile(r"@[0-9a-f]{40}$")
_USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.I | re.M)
_UNTRUSTED_CTX = re.compile(r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|"
                            r"review|head_commit|inputs)\.[^}]*\}\}", re.I)
_SECRET_ECHO = re.compile(r"(echo|print|printf|cat)\b[^\n]*\$\{\{\s*secrets\.", re.I)


def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as fh:
            return fh.read()
    except Exception:
        return ""


def _find_files(root: str) -> dict:
    """Locate CI/CD definition files under a repo root."""
    gh, other = [], {}
    wf_dir = os.path.join(root, ".github", "workflows")
    if os.path.isdir(wf_dir):
        for fn in sorted(os.listdir(wf_dir)):
            if fn.lower().endswith((".yml", ".yaml")):
                gh.append(os.path.join(wf_dir, fn))
    gl = os.path.join(root, ".gitlab-ci.yml")
    if os.path.isfile(gl):
        other["gitlab"] = gl
    jk = os.path.join(root, "Jenkinsfile")
    if os.path.isfile(jk):
        other["jenkins"] = jk
    return {"github": gh, "other": other}


def _analyze_github(path: str, rel: str) -> list[dict]:
    out: list[dict] = []
    text = _read(path)
    if not text:
        return out
    low = text.lower()

    # excessive permissions
    if re.search(r"permissions:\s*write-all", low):
        out.append(finding("cicd.excessive_permissions",
                           f"{rel}: 'permissions: write-all' grants the workflow token full write access."))
    else:
        # any explicit write: permission at token scope
        for m in re.finditer(r"(\w[\w-]*):\s*write\b", low):
            scope = m.group(1)
            if scope in ("contents", "packages", "id-token", "deployments",
                         "actions", "pull-requests", "issues", "checks"):
                out.append(finding("cicd.excessive_permissions",
                                   f"{rel}: workflow grants '{scope}: write' — confirm it is required."))
                break

    # pull_request_target + checkout of PR head (classic RCE-on-CI pattern)
    if "pull_request_target" in low and re.search(r"uses:\s*actions/checkout", low):
        # heuristic: checkout with an explicit ref pulling the PR head
        if re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", low) or "actions/checkout" in low:
            out.append(finding("cicd.pr_target_checkout",
                               f"{rel}: 'pull_request_target' checks out PR-controlled code — untrusted code can "
                               f"run with repository secrets/token."))

    # untrusted context interpolated into run: scripts (script injection).
    # Handle both inline `run: echo ${{...}}` and multi-line `run: |` blocks.
    in_run = False
    flagged_injection = False
    for line in text.splitlines():
        is_run_line = re.match(r"\s*-?\s*run:\s*", line) is not None
        if is_run_line:
            in_run = True
            if not flagged_injection and _UNTRUSTED_CTX.search(line):
                out.append(finding("cicd.script_injection",
                                   f"{rel}: untrusted `${{{{ github.event.* }}}}` interpolated into a run step "
                                   f"({line.strip()[:80]}) — enables shell injection."))
                flagged_injection = True
            continue
        if in_run:
            # still inside an indented run: | block?
            if line.strip() and not line.startswith((" ", "\t")):
                in_run = False
            elif not flagged_injection and _UNTRUSTED_CTX.search(line):
                out.append(finding("cicd.script_injection",
                                   f"{rel}: untrusted `${{{{ github.event.* }}}}` interpolated into a run step "
                                   f"({line.strip()[:80]}) — enables shell injection."))
                flagged_injection = True

    # unpinned third-party actions
    for m in _USES_RE.finditer(text):
        ref = m.group(1).strip().strip("'\"")
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if "@" not in ref:
            continue
        owner = ref.split("/")[0].lower()
        if owner in ("actions", "github"):
            continue   # first-party; still ideally pinned but lower risk
        if not _SHA_RE.search(ref):
            out.append(finding("cicd.untrusted_action",
                               f"{rel}: third-party action '{ref}' is pinned to a mutable tag/branch, "
                               f"not a commit SHA."))

    # secret echoed in a shell step
    if _SECRET_ECHO.search(text):
        out.append(finding("cicd.secret_exposure",
                           f"{rel}: a shell step echoes/prints a ${{{{ secrets.* }}}} value — risks leaking it to logs."))
    return out


def _analyze_generic(path: str, rel: str, kind: str) -> list[dict]:
    out: list[dict] = []
    text = _read(path)
    if not text:
        return out
    # unpinned images / actions and secret echoes are common across systems
    if _SECRET_ECHO.search(text) or re.search(r"(echo|print)\b[^\n]*\$\{?[A-Z_]*(SECRET|TOKEN|PASSWORD|KEY)", text):
        out.append(finding("cicd.secret_exposure",
                           f"{rel} ({kind}): a step appears to print a secret/credential to the build log."))
    # Jenkins: string-interpolated shell with params (injection)
    if kind == "jenkins" and re.search(r'sh\s+"[^"]*\$\{?(params|env)\.', text):
        out.append(finding("cicd.script_injection",
                           f"{rel} (jenkins): parameter/env value interpolated into a sh step — injection risk."))
    return out


def analyze_dir(root: str) -> list[dict]:
    """Analyze all CI/CD definitions under a repo root. Returns finding dicts."""
    if not os.path.isdir(root):
        return []
    files = _find_files(root)
    out: list[dict] = []
    for p in files["github"]:
        out += _analyze_github(p, os.path.relpath(p, root))
    for kind, p in files["other"].items():
        out += _analyze_generic(p, os.path.relpath(p, root), kind)
    return out


def files_present(root: str) -> bool:
    f = _find_files(root)
    return bool(f["github"] or f["other"])
