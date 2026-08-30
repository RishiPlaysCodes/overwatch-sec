#!/usr/bin/env python3
"""
core/target_detector.py — identify what a target IS, so the right pipeline runs.

Returns a target descriptor: {kind, value, hints}. `kind` maps to a scanner
pipeline. Detection is heuristic and plugin-friendly — new detectors can be
registered without touching callers.
"""

from __future__ import annotations

import ipaddress
import os
import re

# image ref like name:tag / repo/name:tag / registry/ns/name@sha256:...
_IMAGE_RE = re.compile(r"^([a-z0-9.\-]+(?::[0-9]+)?/)?[a-z0-9._\-/]+(:[\w.\-]+|@sha256:[0-9a-f]{64})$", re.I)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)

_IAC_MARKERS = (".tf", ".tf.json", ".template")
_CODE_MANIFESTS = {"requirements.txt", "package.json", "go.mod", "pom.xml", "build.gradle",
                   "Gemfile", "composer.json", "Cargo.toml", "pyproject.toml"}
_K8S_MARKERS = ("deployment.yaml", "kustomization.yaml", "chart.yaml")


def _is_ip_or_cidr(t: str) -> bool:
    try:
        ipaddress.ip_network(t, strict=False)
        return True
    except ValueError:
        return False


def detect(target: str) -> dict:
    t = target.strip()
    low = t.lower()

    # cloud providers
    if low in ("aws", "azure", "gcp"):
        return {"kind": "cloud", "value": low, "hints": {"provider": low}}

    # mobile apps
    if low.endswith((".apk", ".aab", ".xapk")):
        return {"kind": "mobile", "value": t, "hints": {"os": "android"}}
    if low.endswith(".ipa"):
        return {"kind": "mobile", "value": t, "hints": {"os": "ios"}}

    # directories: iac / k8s / source
    if os.path.isdir(t):
        has_iac = has_code = has_k8s = False
        try:
            for name in os.listdir(t):
                nl = name.lower()
                if nl.endswith(_IAC_MARKERS):
                    has_iac = True
                if nl in _K8S_MARKERS:
                    has_k8s = True
                if nl in _CODE_MANIFESTS or nl.endswith((".py", ".js", ".ts", ".go", ".java", ".rb", ".php")):
                    has_code = True
        except OSError:
            pass
        if has_k8s:
            return {"kind": "kubernetes", "value": t, "hints": {}}
        if has_iac:
            return {"kind": "cloud", "value": t, "hints": {"iac": True}}
        return {"kind": "code", "value": t, "hints": {"code": has_code}}

    # explicit URL -> web/api
    if low.startswith(("http://", "https://")):
        kind = "api" if re.search(r"/(api|v\d|graphql|rest)(/|$)", low) else "web"
        return {"kind": kind, "value": t, "hints": {}}

    # IP / CIDR -> network
    if _is_ip_or_cidr(t):
        return {"kind": "network", "value": t, "hints": {"cidr": "/" in t}}

    # container image ref (tag or digest, and not a plain domain)
    last = t.split("/")[-1]
    if _IMAGE_RE.match(t) and (":" in last or "@sha256:" in t) and not _DOMAIN_RE.match(t):
        return {"kind": "container", "value": t, "hints": {}}

    # bare domain -> recon (attack-surface) by default; single hostname -> web
    if _DOMAIN_RE.match(t):
        # apex (2 labels) => recon whole surface; deeper host => web
        labels = t.split(".")
        if len(labels) <= 2:
            return {"kind": "recon", "value": t, "hints": {"domain": True}}
        return {"kind": "web", "value": t, "hints": {"host": True}}

    # fallback
    return {"kind": "web", "value": t, "hints": {"fallback": True}}


# maps target kind -> which scanner module handles it
KIND_TO_SCANNER = {
    "recon": "scanner_recon",
    "web": "scanner_web",
    "api": "scanner_api",            # dedicated OWASP API Security checks
    "network": "scanner_network",
    "mobile": "scanner_mobile",
    "cloud": "scanner_cloud",
    "container": "scanner_container",
    "kubernetes": "scanner_kubernetes",   # dedicated k8s manifest audit
    "code": "scanner_code",
}
