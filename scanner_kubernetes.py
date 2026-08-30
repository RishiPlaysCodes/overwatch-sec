#!/usr/bin/env python3
"""
scanner_kubernetes.py — Kubernetes manifest & config security audit.

Points at a directory of k8s manifests (or a single YAML) and runs SAFE,
static checks against CIS / NSA-CISA hardening guidance:
  - privileged containers / allowPrivilegeEscalation
  - hostPath volume mounts (and docker.sock)
  - wildcard RBAC (Role/ClusterRole with '*')
  - hostNetwork / hostPID / hostIPC
  - missing NetworkPolicy in a namespace with workloads

Optional tools (auto-detected): kube-bench, trivy (config), checkov, kubescape.
Static parsing is regex/scan-based so it works without PyYAML.
"""

from __future__ import annotations

import os
import re

from common import banner, finding, have, info, ok, run, warn

_MANIFEST_EXT = (".yaml", ".yml", ".json")


def _iter_files(path: str):
    if os.path.isfile(path):
        yield path
        return
    for root, _d, files in os.walk(path):
        if any(seg in root for seg in (".git", "node_modules")):
            continue
        for f in files:
            if f.endswith(_MANIFEST_EXT):
                yield os.path.join(root, f)


def _audit_text(text: str, rel: str, out: list, flags: dict):
    low = text.lower().replace(" ", "")
    if "privileged:true" in low:
        out.append(finding("k8s.privileged", f"{rel}: privileged: true"))
    if "allowprivilegeescalation:true" in low:
        out.append(finding("k8s.privileged", f"{rel}: allowPrivilegeEscalation: true"))
    if "hostpath:" in low or re.search(r"hostPath", text):
        detail = "docker.sock" if "docker.sock" in low else "host path"
        out.append(finding("k8s.hostpath", f"{rel}: hostPath volume ({detail})"))
    if "hostnetwork:true" in low or "hostpid:true" in low or "hostipc:true" in low:
        out.append(finding("k8s.hostnet", f"{rel}: hostNetwork/hostPID/hostIPC enabled"))
    # wildcard RBAC
    if re.search(r"kind:\s*(Cluster)?Role\b", text) and re.search(r'(verbs|resources|apiGroups):\s*\[?\s*["\']?\*', text):
        out.append(finding("k8s.rbac_wildcard", f"{rel}: RBAC rule uses '*'"))
    # track workloads vs networkpolicy for the netpol check
    if re.search(r"kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|ReplicaSet)\b", text):
        flags["workloads"] = True
    if re.search(r"kind:\s*NetworkPolicy\b", text):
        flags["netpol"] = True


def scan(target: str, outdir: str, skip: set) -> dict:
    result = {"profile": "kubernetes", "target": target, "findings": [], "tools": []}
    banner(f"KUBERNETES — manifest audit on {target}")
    out, flags = [], {"workloads": False, "netpol": False}
    files = list(_iter_files(target))
    info(f"scanning {len(files)} manifest file(s)")
    for fp in files:
        try:
            with open(fp, "r", errors="ignore") as fh:
                text = fh.read()
        except Exception:
            continue
        _audit_text(text, os.path.relpath(fp, target) if os.path.isdir(target) else os.path.basename(fp), out, flags)
    if flags["workloads"] and not flags["netpol"]:
        out.append(finding("k8s.no_netpol", "Workloads present but no NetworkPolicy found (flat pod network)"))

    # de-dup
    seen = set()
    for f in out:
        k = (f["id"], f["evidence"])
        if k not in seen:
            seen.add(k)
            result["findings"].append(f)
    ok(f"{len(result['findings'])} k8s finding(s)")

    # optional deep tools
    banner("KUBERNETES — optional tools (kube-bench / trivy / checkov / kubescape)")
    for tool, args, outfile in (
        ("trivy", ["trivy", "config", target], "trivy-k8s.txt"),
        ("checkov", ["checkov", "-d", target, "--compact", "--quiet"], "checkov-k8s.txt"),
        ("kubescape", ["kubescape", "scan", target], "kubescape.txt"),
    ):
        if have(tool) and tool not in skip:
            rc, o = run(args, timeout=900)
            with open(os.path.join(outdir, outfile), "w") as fh:
                fh.write(o)
            result["tools"].append({"tool": tool, "status": "done", "output": os.path.join(outdir, outfile)})
        else:
            result["tools"].append({"tool": tool, "status": "skipped", "reason": "not installed"})
    if have("kube-bench"):
        result["tools"].append({"tool": "kube-bench", "status": "available",
                                "reason": "run against a live cluster node for CIS benchmark"})
    return result
