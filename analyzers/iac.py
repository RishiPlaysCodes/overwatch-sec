#!/usr/bin/env python3
"""
analyzers/iac.py — dependency-free Infrastructure-as-Code security analyzer.

Statically analyzes IaC files in a repository and emits normalized findings
(via common.finding). No external tools, no network. Pattern/line based — findings
are DETECTED config facts; deployment impact is confirmed by review.

Supported:
  - Dockerfile(s)          -> container.misconfig / iac.hardcoded_secret
  - Terraform (*.tf)       -> iac.public_exposure / iac.insecure_default / iac.hardcoded_secret
  - Kubernetes YAML        -> k8s.privileged / k8s.hostpath / k8s.hostnet / k8s.rbac_wildcard

Reuses existing KB ids (container.*, k8s.*, iac.*) so the report enriches them
with attack scenario + remediation consistently.
"""

from __future__ import annotations

import os
import re

try:
    from common import finding
except Exception:  # pragma: no cover
    def finding(fid, evidence, severity_override=None):
        return {"id": fid, "evidence": evidence, "severity": severity_override or "info"}

_SKIP_DIRS = {".git", "node_modules", ".terraform", "venv", ".venv", "dist", "build", "__pycache__"}
_SECRET_ASSIGN = re.compile(
    r"(?i)(password|passwd|secret|access[_-]?key|secret[_-]?key|api[_-]?key|token|private[_-]?key)"
    r"\s*[=:]\s*['\"][^'\"]{6,}['\"]")


def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as fh:
            return fh.read()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------
def analyze_dockerfile(path: str, rel: str) -> list[dict]:
    out: list[dict] = []
    text = _read(path)
    if not text:
        return out
    lines = [l.rstrip() for l in text.splitlines()]
    has_user_nonroot = False
    for l in lines:
        s = l.strip()
        ls = s.lower()
        if ls.startswith("from ") and ls.rstrip().endswith(":latest"):
            out.append(finding("container.misconfig",
                               f"{rel}: base image uses ':latest' (unpinned) — builds are non-reproducible."))
        if ls.startswith("from ") and ":" not in s.split()[1] and "@" not in s:
            out.append(finding("container.misconfig",
                               f"{rel}: base image '{s.split()[1]}' has no explicit tag/digest (implicitly latest)."))
        if ls.startswith("user "):
            u = s.split(None, 1)[1].strip().strip('"').lower()
            has_user_nonroot = u not in ("root", "0", "0:0")
        if ls.startswith("add ") and re.search(r"add\s+https?://", ls):
            out.append(finding("container.misconfig",
                               f"{rel}: 'ADD <url>' fetches remote content into the image — use verified COPY."))
        if re.search(r"(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(sh|bash)", ls):
            out.append(finding("container.misconfig",
                               f"{rel}: pipes a downloaded script straight to a shell (curl|sh) — unverified code."))
        if _SECRET_ASSIGN.search(s) and (ls.startswith("env ") or ls.startswith("arg ") or "=" in s):
            if ls.startswith(("env ", "arg ")):
                out.append(finding("iac.hardcoded_secret",
                                   f"{rel}: secret hardcoded in a Docker ENV/ARG ({s[:60]})."))
    if not has_user_nonroot:
        out.append(finding("container.misconfig",
                           f"{rel}: no non-root USER directive — container runs as root by default."))
    return out


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------
def analyze_terraform(path: str, rel: str) -> list[dict]:
    out: list[dict] = []
    text = _read(path)
    if not text:
        return out
    low = text.lower()
    if "0.0.0.0/0" in text and re.search(r"(ingress|cidr_blocks|source_ranges)", low):
        out.append(finding("iac.public_exposure",
                           f"{rel}: security-group/ingress rule allows 0.0.0.0/0 (open to the whole internet)."))
    if re.search(r'acl\s*=\s*"public-read(-write)?"', low):
        out.append(finding("iac.public_exposure",
                           f"{rel}: storage ACL is public-read/-write — objects are world-accessible."))
    if re.search(r'(encrypted|encryption)\s*=\s*false', low) or re.search(r'skip_final_snapshot\s*=\s*true', low):
        out.append(finding("iac.insecure_default",
                           f"{rel}: encryption disabled (or backups skipped) on a resource."))
    for m in _SECRET_ASSIGN.finditer(text):
        # ignore var references like password = var.db_password
        seg = text[m.start():m.end()]
        if "var." in seg or "data." in seg or "${" in seg:
            continue
        out.append(finding("iac.hardcoded_secret",
                           f"{rel}: hardcoded secret in Terraform ({seg[:60]})."))
        break
    return out


# ---------------------------------------------------------------------------
# Kubernetes YAML
# ---------------------------------------------------------------------------
def _looks_like_k8s(text: str) -> bool:
    return bool(re.search(r"^\s*apiversion:", text, re.I | re.M)) and \
           bool(re.search(r"^\s*kind:", text, re.I | re.M))


def analyze_k8s(path: str, rel: str) -> list[dict]:
    out: list[dict] = []
    text = _read(path)
    if not text or not _looks_like_k8s(text):
        return out
    low = text.lower()
    if re.search(r"privileged:\s*true", low):
        out.append(finding("k8s.privileged", f"{rel}: container securityContext sets privileged: true."))
    if re.search(r"allowprivilegeescalation:\s*true", low):
        out.append(finding("k8s.privileged", f"{rel}: allowPrivilegeEscalation: true."))
    if re.search(r"hostpath:", low):
        out.append(finding("k8s.hostpath", f"{rel}: pod mounts a hostPath volume from the node filesystem."))
    if re.search(r"host(network|pid|ipc):\s*true", low):
        out.append(finding("k8s.hostnet", f"{rel}: pod shares a host namespace (hostNetwork/hostPID/hostIPC)."))
    # RBAC wildcards
    if re.search(r"kind:\s*(cluster)?role", low):
        if re.search(r'(verbs|resources|apigroups):\s*\[?\s*["\']?\*', low):
            out.append(finding("k8s.rbac_wildcard",
                               f"{rel}: Role/ClusterRole grants wildcard '*' verbs/resources (admin-equivalent)."))
    return out


# ---------------------------------------------------------------------------
def analyze_dir(root: str) -> list[dict]:
    """Walk a repo and analyze every Dockerfile / *.tf / Kubernetes YAML."""
    if not os.path.isdir(root):
        return []
    out: list[dict] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            p = os.path.join(base, fn)
            rel = os.path.relpath(p, root)
            fl = fn.lower()
            try:
                if os.path.getsize(p) > 1_500_000:
                    continue
            except OSError:
                continue
            if fl == "dockerfile" or fl.startswith("dockerfile.") or fl.endswith(".dockerfile"):
                out += analyze_dockerfile(p, rel)
            elif fl.endswith(".tf") or fl.endswith(".tf.json"):
                out += analyze_terraform(p, rel)
            elif fl.endswith((".yaml", ".yml")):
                out += analyze_k8s(p, rel)
    return out


def files_present(root: str) -> bool:
    if not os.path.isdir(root):
        return False
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            fl = fn.lower()
            if fl == "dockerfile" or fl.endswith((".tf", ".tf.json")):
                return True
            if fl.endswith((".yaml", ".yml")) and _looks_like_k8s(_read(os.path.join(base, fn))):
                return True
    return False
